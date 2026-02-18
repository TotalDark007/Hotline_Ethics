"""Add assigned_user_id to report

Revision ID: a1a2b3c4d5e6
Revises: 644773653bf6
Create Date: 2025-09-13 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a1a2b3c4d5e6'
down_revision = '644773653bf6'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('report', schema=None) as batch_op:
        batch_op.add_column(sa.Column('assigned_user_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key('fk_report_assigned_user', 'user', ['assigned_user_id'], ['id'])
        batch_op.create_index('ix_report_assigned_user_id', ['assigned_user_id'])


def downgrade():
    with op.batch_alter_table('report', schema=None) as batch_op:
        batch_op.drop_index('ix_report_assigned_user_id')
        batch_op.drop_constraint('fk_report_assigned_user', type_='foreignkey')
        batch_op.drop_column('assigned_user_id')

