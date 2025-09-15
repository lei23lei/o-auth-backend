"""create_users_table

Revision ID: a426b0937db8
Revises: 876c4c5f159f
Create Date: 2025-09-15 15:28:50.567291

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a426b0937db8'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create users table with all fields from the updated User model
    op.create_table('users',
        sa.Column('id', sa.dialects.postgresql.UUID(as_uuid=True), nullable=False, default=sa.text('gen_random_uuid()')),
        sa.Column('image', sa.String(), nullable=True),
        sa.Column('email', sa.String(), nullable=False),
        sa.Column('password', sa.String(), nullable=True),
        sa.Column('name', sa.String(), nullable=True),
        sa.Column('provider', sa.String(), nullable=False, server_default='email'),
        sa.Column('provider_id', sa.String(), nullable=True),
        sa.Column('username', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True, default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=True, default=sa.func.now()),
        sa.Column('reset_password_token', sa.String(), nullable=True),
        sa.Column('reset_password_token_expires', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes
    op.create_index(op.f('ix_users_id'), 'users', ['id'], unique=False)
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_provider_id'), 'users', ['provider_id'], unique=False)
    op.create_unique_constraint('uq_users_reset_password_token', 'users', ['reset_password_token'])


def downgrade() -> None:
    # Drop the users table
    op.drop_table('users')
