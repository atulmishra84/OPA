"""Attribute change engine for synchronising user attributes across directory services."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol, Sequence, Tuple


class AttributeChangeError(RuntimeError):
    """Base exception for attribute change operations."""

    def __init__(self, message: str, *, service: Optional[str] = None, cause: Optional[BaseException] = None) -> None:
        super().__init__(message)
        self.service = service
        self.__cause__ = cause


class UnknownDirectoryServiceError(AttributeChangeError):
    """Raised when an attribute change targets a non-existent directory service."""

    def __init__(self, service: str) -> None:
        super().__init__(f"Unknown directory service: {service}", service=service)


class DirectoryService(Protocol):
    """Protocol describing the interface required by the change engine."""

    name: str

    def update_attribute(self, user_id: str, attribute: str, value: Any) -> None:
        """Persist an attribute change for ``user_id`` within the directory."""


UpdateHandler = Callable[[str, str, Any], None]


@dataclass(frozen=True)
class AttributeChangeRequest:
    """Represents a single attribute change that should be propagated."""

    user_id: str
    attribute: str
    value: Any
    services: Optional[Tuple[str, ...]] = None

    def __post_init__(self) -> None:
        if not self.user_id:
            raise ValueError("user_id must be provided")
        if not self.attribute:
            raise ValueError("attribute must be provided")

        if self.services is not None:
            services: Sequence[str] = self.services
            normalized: List[str] = []
            for service in services:
                if not isinstance(service, str) or not service.strip():
                    raise ValueError("service names must be non-empty strings")
                normalized.append(service.strip())
            object.__setattr__(self, "services", tuple(normalized))


@dataclass
class AttributeChangeResult:
    """Outcome of applying an :class:`AttributeChangeRequest`."""

    request: AttributeChangeRequest
    successful: List[str] = field(default_factory=list)
    failures: Dict[str, AttributeChangeError] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return not self.failures

    def raise_if_failed(self) -> None:
        if self.failures:
            messages = ", ".join(f"{service}: {error}" for service, error in self.failures.items())
            raise AttributeChangeError(
                f"One or more directory updates failed: {messages}",
                cause=next(iter(self.failures.values())),
            )


class AttributeChangeEngine:
    """Coordinate attribute changes across multiple directory services."""

    def __init__(self) -> None:
        self._services: Dict[str, UpdateHandler] = {}

    # ------------------------------------------------------------------
    # Service registration helpers
    # ------------------------------------------------------------------
    def register_service(
        self,
        service: DirectoryService | UpdateHandler,
        *,
        name: Optional[str] = None,
        replace: bool = False,
    ) -> None:
        """Register a directory service implementation with the engine.

        Args:
            service: Either an object implementing :class:`DirectoryService`
                or a callable with the signature ``(user_id, attribute, value)``.
            name: Optional explicit service name. If omitted and ``service`` is an
                object, the ``name`` attribute will be used.
            replace: If ``True`` existing registrations with the same name will be
                replaced. The default is to raise a :class:`ValueError`.
        """

        resolved_name = self._resolve_service_name(service, name)
        if resolved_name in self._services and not replace:
            raise ValueError(f"Service '{resolved_name}' is already registered")

        handler = self._coerce_handler(service)
        self._services[resolved_name] = handler

    def unregister_service(self, name: str) -> None:
        """Remove a previously registered directory service."""

        self._services.pop(name, None)

    def services(self) -> Tuple[str, ...]:
        """Return a tuple of registered service names."""

        return tuple(self._services.keys())

    # ------------------------------------------------------------------
    # Attribute propagation
    # ------------------------------------------------------------------
    def apply_change(self, change: AttributeChangeRequest) -> AttributeChangeResult:
        """Apply a single attribute change to all targeted services."""

        result = AttributeChangeResult(request=change)
        target_services = change.services or self.services()

        for service_name in target_services:
            handler = self._services.get(service_name)
            if handler is None:
                result.failures[service_name] = UnknownDirectoryServiceError(service_name)
                continue

            try:
                handler(change.user_id, change.attribute, change.value)
            except AttributeChangeError as error:
                result.failures[service_name] = AttributeChangeError(
                    str(error), service=service_name, cause=error
                )
            except Exception as error:  # pragma: no cover - defensive
                result.failures[service_name] = AttributeChangeError(
                    f"Unexpected error: {error}", service=service_name, cause=error
                )
            else:
                result.successful.append(service_name)

        return result

    def apply_changes(self, changes: Iterable[AttributeChangeRequest]) -> List[AttributeChangeResult]:
        """Apply multiple changes and return their results."""

        return [self.apply_change(change) for change in changes]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _resolve_service_name(
        service: DirectoryService | UpdateHandler, name: Optional[str]
    ) -> str:
        if name is not None:
            resolved = name.strip()
            if not resolved:
                raise ValueError("Service name must not be empty")
            return resolved

        if callable(service) and not hasattr(service, "name"):
            raise ValueError("A name must be provided when registering a callable")

        resolved = getattr(service, "name", None)
        if not isinstance(resolved, str) or not resolved.strip():
            raise ValueError("Service object must define a non-empty 'name' attribute")
        return resolved.strip()

    @staticmethod
    def _coerce_handler(service: DirectoryService | UpdateHandler) -> UpdateHandler:
        if callable(service) and not hasattr(service, "update_attribute"):
            return service  # type: ignore[return-value]
        return getattr(service, "update_attribute")


__all__ = [
    "AttributeChangeEngine",
    "AttributeChangeError",
    "AttributeChangeRequest",
    "AttributeChangeResult",
    "DirectoryService",
    "UnknownDirectoryServiceError",
]
