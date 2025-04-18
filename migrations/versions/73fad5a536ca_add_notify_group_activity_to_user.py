"""Add notify_group_activity to User

Revision ID: 73fad5a536ca
Revises: 
Create Date: 2025-04-02 19:50:07.098082

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '73fad5a536ca'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('notify_group_activity', sa.Boolean(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('notify_group_activity')

    # ### end Alembic commands ###
