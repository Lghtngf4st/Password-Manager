from __future__ import annotations

from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func

db = SQLAlchemy()


def utcnow() -> datetime:
    # Application side UTC timestamps
    return datetime.now(timezone.utc)


class User(db.Model):
    __tablename__ = "users"
    
    id = db.Column(db.Integer, primary_key=True)
    
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    
    # Per-user salt for deriving a vault encryption key
    kdf_salt = db.Column(db.LargeBinary, nullable=False)
    
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=True)
    
    # Relationship: one user has many vault items
    
    vault_items = db.relationship(
        "VaultItem",
        back_populates="user",
        cascade="all, delete-orphan",
        passive_deletes=True,
        lazy="select",
    )
    
    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r}>"
    

class VaultItem(db.Model):
    __tablename__ = "vault_items"
    
    id = db.Column(db.Integer, primary_key=True)
    
    user_id = db.Column(
        db.Integer,
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    
    # Keep lable/url plaintext for usability (search/sort). Encrypt the rest
    label = db.Column(db.String(128), nullable=False, index=True)
    url = db.Column(db.String(512), nullable=True)
    
    login_username_encrypted = db.Column(db.LargeBinary, nullable=True)
    login_password_encrypted = db.Column(db.LargeBinary, nullable=False)
    notes_encrypted = db.Column(db.LargeBinary, nullable=True)
    
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )
    
    user = db.relationship("User", back_populates="vault_items")
    
    def __repr__(self) -> str:
        return f"<VaultItem id={self.id} user_id={self.user_id} label={self.label!r}>"