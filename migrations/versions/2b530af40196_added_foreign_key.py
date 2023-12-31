"""added foreign key

Revision ID: 2b530af40196
Revises: 
Create Date: 2023-08-25 19:39:21.034378

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '2b530af40196'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('uploaded_files',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('file_name', sa.String(length=120), nullable=False),
    sa.Column('file_path', sa.String(length=120), nullable=False),
    sa.Column('date_added', sa.DateTime(), nullable=True),
    sa.Column('user_id', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('uploaded_files')
    # ### end Alembic commands ###
