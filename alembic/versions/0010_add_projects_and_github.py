"""Add Phase 3 projects, project_images, github_connections, and github_oauth_states tables.

Revision ID: 0010_add_projects_and_github
Revises: 0009_add_document_analyses
Create Date: 2026-11-27 12:45:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0010_add_projects_and_github"
down_revision: Union[str, Sequence[str], None] = "0009_add_document_analyses"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create Phase 3 Projects Portfolio and GitHub Integration tables."""
    op.create_table(
        "projects",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("summary", sa.String(length=500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "category",
            sa.String(length=80),
            server_default=sa.text("'General'"),
            nullable=False,
        ),
        sa.Column(
            "technologies",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("github_url", sa.String(length=512), nullable=True),
        sa.Column("live_url", sa.String(length=512), nullable=True),
        sa.Column("start_date", sa.Date(), nullable=True),
        sa.Column("end_date", sa.Date(), nullable=True),
        sa.Column(
            "is_ongoing",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "featured",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "display_order",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "visibility",
            sa.String(length=16),
            server_default=sa.text("'private'"),
            nullable=False,
        ),
        sa.Column("github_repo_id", sa.BigInteger(), nullable=True),
        sa.Column("github_repo_full_name", sa.String(length=255), nullable=True),
        sa.Column("github_imported_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "title = btrim(title) AND char_length(title) BETWEEN 1 AND 200",
            name="ck_projects_title_valid",
        ),
        sa.CheckConstraint(
            "summary = btrim(summary) AND char_length(summary) BETWEEN 1 AND 500",
            name="ck_projects_summary_valid",
        ),
        sa.CheckConstraint(
            "category = btrim(category) AND char_length(category) BETWEEN 1 AND 80",
            name="ck_projects_category_valid",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(technologies) = 'array'",
            name="ck_projects_technologies_array",
        ),
        sa.CheckConstraint(
            "NOT (is_ongoing = true AND end_date IS NOT NULL)",
            name="ck_projects_ongoing_no_end_date",
        ),
        sa.CheckConstraint(
            "start_date IS NULL OR end_date IS NULL OR end_date >= start_date",
            name="ck_projects_date_order_valid",
        ),
        sa.CheckConstraint(
            "display_order >= 0",
            name="ck_projects_display_order_non_negative",
        ),
        sa.CheckConstraint(
            "visibility IN ('private', 'public')",
            name="ck_projects_visibility_valid",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_projects_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_projects"),
    )
    op.create_index("ix_projects_user_id", "projects", ["user_id"], unique=False)
    op.create_index(
        "ix_projects_user_visibility",
        "projects",
        ["user_id", "visibility"],
        unique=False,
    )
    op.create_index(
        "uq_projects_user_github_repo_id",
        "projects",
        ["user_id", "github_repo_id"],
        unique=True,
        postgresql_where=sa.text("github_repo_id IS NOT NULL"),
    )

    op.create_table(
        "project_images",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("project_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("storage_backend", sa.String(length=16), nullable=False),
        sa.Column("storage_key", sa.String(length=255), nullable=False),
        sa.Column("mime_type", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("alt", sa.String(length=255), nullable=True),
        sa.Column(
            "display_order",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "storage_backend IN ('local', 's3')",
            name="ck_project_images_storage_backend_valid",
        ),
        sa.CheckConstraint(
            "mime_type IN ('image/jpeg', 'image/png', 'image/webp')",
            name="ck_project_images_mime_type_valid",
        ),
        sa.CheckConstraint(
            "size_bytes > 0",
            name="ck_project_images_size_bytes_positive",
        ),
        sa.CheckConstraint(
            "display_order >= 0",
            name="ck_project_images_display_order_non_negative",
        ),
        sa.ForeignKeyConstraint(
            ["project_id"],
            ["projects.id"],
            name="fk_project_images_project_id_projects",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_project_images_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_project_images"),
        sa.UniqueConstraint("storage_key", name="uq_project_images_storage_key"),
    )
    op.create_index(
        "ix_project_images_project_id",
        "project_images",
        ["project_id"],
        unique=False,
    )
    op.create_index(
        "ix_project_images_user_id",
        "project_images",
        ["user_id"],
        unique=False,
    )

    op.create_table(
        "github_connections",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("github_user_id", sa.String(length=64), nullable=False),
        sa.Column("username", sa.String(length=120), nullable=False),
        sa.Column("avatar_url", sa.String(length=512), nullable=True),
        sa.Column("access_token_encrypted", sa.Text(), nullable=False),
        sa.Column("token_scope", sa.String(length=255), nullable=True),
        sa.Column("connected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "github_user_id = btrim(github_user_id) AND char_length(github_user_id) > 0",
            name="ck_github_connections_github_user_id_valid",
        ),
        sa.CheckConstraint(
            "username = btrim(username) AND char_length(username) > 0",
            name="ck_github_connections_username_valid",
        ),
        sa.CheckConstraint(
            "length(btrim(access_token_encrypted)) > 0",
            name="ck_github_connections_token_not_empty",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_github_connections_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_github_connections"),
        sa.UniqueConstraint("user_id", name="uq_github_connections_user_id"),
    )

    op.create_table(
        "github_oauth_states",
        sa.Column(
            "id",
            sa.Uuid(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("state_hash", sa.CHAR(length=64), nullable=False),
        sa.Column("redirect_uri", sa.String(length=512), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "state_hash ~ '^[0-9a-f]{64}$'",
            name="ck_github_oauth_states_state_hash_hex",
        ),
        sa.CheckConstraint(
            "length(btrim(redirect_uri)) > 0 AND redirect_uri = btrim(redirect_uri)",
            name="ck_github_oauth_states_redirect_uri_valid",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_github_oauth_states_user_id_users",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_github_oauth_states"),
        sa.UniqueConstraint("state_hash", name="uq_github_oauth_states_state_hash"),
    )
    op.create_index(
        "ix_github_oauth_states_expires_at",
        "github_oauth_states",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_github_oauth_states_user_id",
        "github_oauth_states",
        ["user_id"],
        unique=False,
    )


def downgrade() -> None:
    """Drop Phase 3 Projects Portfolio and GitHub Integration tables."""
    op.drop_index("ix_github_oauth_states_user_id", table_name="github_oauth_states")
    op.drop_index("ix_github_oauth_states_expires_at", table_name="github_oauth_states")
    op.drop_table("github_oauth_states")

    op.drop_table("github_connections")

    op.drop_index("ix_project_images_user_id", table_name="project_images")
    op.drop_index("ix_project_images_project_id", table_name="project_images")
    op.drop_table("project_images")

    op.drop_index(
        "uq_projects_user_github_repo_id",
        table_name="projects",
        postgresql_where=sa.text("github_repo_id IS NOT NULL"),
    )
    op.drop_index("ix_projects_user_visibility", table_name="projects")
    op.drop_index("ix_projects_user_id", table_name="projects")
    op.drop_table("projects")
