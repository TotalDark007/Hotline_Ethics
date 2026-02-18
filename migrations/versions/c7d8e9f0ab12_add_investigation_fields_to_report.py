"""Add investigation fields to report

Revision ID: c7d8e9f0ab12
Revises: a1a2b3c4d5e6
Create Date: 2025-09-13 00:15:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c7d8e9f0ab12'
down_revision = 'a1a2b3c4d5e6'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('report', schema=None) as batch_op:
        batch_op.add_column(sa.Column('investigator_notes', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('involved_parties', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('investigator_conclusion', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('investigation_updated_at', sa.DateTime(), nullable=True))


def downgrade():
    with op.batch_alter_table('report', schema=None) as batch_op:
        batch_op.drop_column('investigation_updated_at')
        batch_op.drop_column('investigator_conclusion')
        batch_op.drop_column('involved_parties')
        batch_op.drop_column('investigator_notes')

