"""add company name to response

Revision ID: add_company_name
Revises: 
Create Date: 2024-05-20 10:20:04.517493

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_company_name'
down_revision = None
branch_labels = None
depends_on = None

def upgrade():
    # Add company_name column with nullable=True
    op.add_column('response', sa.Column('company_name', sa.String(100), nullable=True))
    
    # Update existing records to set company_name based on company relationship
    op.execute("""
        UPDATE response 
        SET company_name = (
            SELECT name 
            FROM company 
            WHERE company.id = response.company_id
        )
        WHERE company_id IS NOT NULL
    """)

def downgrade():
    # Remove the company_name column
    op.drop_column('response', 'company_name') 