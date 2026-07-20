from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    """Base for responses read directly off SQLAlchemy instances."""

    model_config = ConfigDict(from_attributes=True)


class Page[T](BaseModel):
    """Envelope for every list endpoint, so pagination is uniform across the API."""

    items: list[T]
    total: int = Field(description="Total rows matching the filter, ignoring pagination")
    limit: int
    offset: int

    @property
    def has_more(self) -> bool:
        return self.offset + len(self.items) < self.total


class PaginationParams(BaseModel):
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)


class MessageResponse(BaseModel):
    message: str


class ErrorDetail(BaseModel):
    detail: str
