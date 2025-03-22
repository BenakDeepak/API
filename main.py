from fastapi import FastAPI, File, UploadFile, HTTPException, Path, Query
import pdfplumber
import re
import mysql.connector
from typing import List, Dict, Optional
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from typing import Optional
from fastapi import Depends, FastAPI, HTTPException, status
from typing import List, Dict, Optional
from fastapi import FastAPI, File, UploadFile, HTTPException, Path, Query, Depends, status
app = FastAPI()
# Authentication settings
SECRET_KEY = "pds4FEQqoT9fG1CzS7MwZcAtJ-ttNSXUILO3KpfZJQU"  # Replace with a secure secret key
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
# Password hashing
pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")# User model
class User(BaseModel):
    username: str
    hashed_password: str

# Token model
class Token(BaseModel):
    access_token: str
    token_type: str

# Token data model
class TokenData(BaseModel):
    username: Optional[str] = None
# Fake user database (replace with your actual user database)
fake_users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash("adminpassword")  # Hashed password
    }
}
# Verify password
def verify_password(plain_password, hashed_password):
# Hash a password
    hashed_password = pwd_context.hash("adminpassword")
    pwd_context.verify("adminpassword", hashed_password)
    return pwd_context.verify(plain_password, hashed_password)

# Get user from database
def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return User(**user_dict)

# Authenticate user
def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

# Create access token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}
# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

@app.get("/invoices/", response_model=List[Dict])
async def get_all_invoices(current_user: User = Depends(get_current_user)):
    try:
        # Connect to MySQL
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Fetch all invoices
        cursor.execute("SELECT * FROM invoices")
        invoices = cursor.fetchall()

        return invoices
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Error fetching invoices: {err}")
    finally:
        # Close the connection
        if connection.is_connected():
            cursor.close()
            connection.close()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins (replace "*" with your frontend URL in production)
    allow_credentials=True,
    allow_methods=["*"],  # Allow all methods
    allow_headers=["*"],  # Allow all headers
)
# Database connection details
db_config = {
    "host": "localhost",
    "user": "root",
    "password": "Benak@2010",
    "database": "APIS"
}

# Pydantic models for request/response validation
class InvoiceItem(BaseModel):
    description: str
    hsn_sac: str
    expiry: str
    quantity: float
    deal: float
    total_quantity: float
    mrp: float
    tax: float
    discount_percent: float
    amount: float

class InvoiceCreate(BaseModel):
    invoice_number: str
    invoice_date: str
    vendor_name: str
    sub_total: float
    discount: float
    grand_total: float
    ewaybill_number: Optional[str] = None
    items: List[InvoiceItem]

class InvoiceUpdate(BaseModel):
    invoice_number: Optional[str] = None
    invoice_date: Optional[str] = None
    vendor_name: Optional[str] = None
    sub_total: Optional[float] = None
    discount: Optional[float] = None
    grand_total: Optional[float] = None
    ewaybill_number: Optional[str] = None

# Regex patterns for invoice-level fields
invoice_patterns = {
    "invoice_number": r"Invoice Number[:]?\s*(\w+)",
    "invoice_date": r"Invoice Date[:]?\s*([A-Za-z]+\s+\d{1,2},\s+\d{4})",
    "vendor_name": r"Vendor \(Bill from\)\s+([A-Za-z\s.]+)\n",
    "sub_total": r"SUBTOTAL[:]?\s*([\d,.]+)",
    "discount": r"DISCOUNT[:]?\s*([\d,.]+)",
    "grand_total": r"GRAND TOTAL[:]?\s*([\d,.]+)",
    "ewaybill_number": r"E-Waybill Number[:]?\s*([A-Z0-9-]+)"  # Adjust if present in the PDF
}

def extract_invoice_data(pdf_path: str) -> Dict:
    with pdfplumber.open(pdf_path) as pdf:
        text = ""
        for page in pdf.pages:
            text += page.extract_text()

    # Extract invoice-level data
    invoice_data = {}
    for field, pattern in invoice_patterns.items():
        match = re.search(pattern, text)
        if match:
            invoice_data[field] = match.group(1).strip()
        else:
            invoice_data[field] = None  # If field not found, set to None

    # Extract item-level data
    items = []
    tables = pdf.pages[0].extract_tables()  # Extract tables from the first page
    for table in tables:
        for row in table[1:]:  # Skip the header row (first row)
            if len(row) >= 10:  # Ensure the row has enough columns
                # Merge split lines for hsn_sac
                hsn_sac = row[1].replace("\n", "").strip()  # Remove newlines and spaces
                item = {
                    "description": row[0].strip(),
                    "hsn_sac": hsn_sac,  # Use the merged hsn_sac
                    "expiry": row[2].strip(),
                    "quantity": float(row[3].strip()),  # Convert to float
                    "deal": float(row[4].strip()),  # Convert to float
                    "total_quantity": float(row[5].strip()),  # Convert to float
                    "mrp": float(row[6].strip()),  # Convert to float
                    "tax": float(row[7].strip()),  # Convert to float
                    "discount_percent": float(row[8].strip()),  # Convert to float
                    "amount": float(row[9].strip())  # Convert to float
                }
                items.append(item)

    return {"invoice_data": invoice_data, "items": items}

def insert_into_mysql(invoice_data: Dict, items: List[Dict]) -> str:
    try:
        # Connect to MySQL
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Insert invoice-level data
        insert_invoice_query = """
            INSERT INTO invoices (
                invoice_number, invoice_date, vendor_name, sub_total, discount, grand_total, ewaybill_number
            ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        invoice_values = (
            invoice_data["invoice_number"],
            invoice_data["invoice_date"],
            invoice_data["vendor_name"],
            float(invoice_data["sub_total"].replace(",", "")),  # Convert to float
            float(invoice_data["discount"].replace(",", "")),  # Convert to float
            float(invoice_data["grand_total"].replace(",", "")),  # Convert to float
            invoice_data["ewaybill_number"]
        )
        cursor.execute(insert_invoice_query, invoice_values)
        invoice_id = cursor.lastrowid  # Get the ID of the inserted invoice

        # Insert item-level data
        insert_item_query = """
            INSERT INTO invoice_items (
                invoice_id, description, hsn_sac, expiry, quantity, deal, total_quantity, mrp, tax, discount_percent, amount
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        for item in items:
            item_values = (
                invoice_id,
                item["description"],
                item["hsn_sac"],
                item["expiry"],
                item["quantity"],
                item["deal"],
                item["total_quantity"],
                item["mrp"],
                item["tax"],
                item["discount_percent"],
                item["amount"]
            )
            cursor.execute(insert_item_query, item_values)

        # Commit the transaction
        connection.commit()
        return "Data inserted into MySQL successfully!"
    except mysql.connector.Error as err:
        return f"Error inserting data into MySQL: {err}"
    finally:
        # Close the connection
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.post("/upload-pdf/")
async def upload_pdf(file: UploadFile = File(...), current_user: User = Depends(get_current_user)):
    # Save the uploaded file temporarily
    file_path = f"temp_{file.filename}"
    with open(file_path, "wb") as buffer:
        buffer.write(file.file.read())

    try:
        # Extract data from the PDF
        extracted_data = extract_invoice_data(file_path)
        invoice_data = extracted_data["invoice_data"]
        items = extracted_data["items"]

        # Insert data into MySQL
        result = insert_into_mysql(invoice_data, items)

        return {"message": result, "invoice_data": invoice_data, "items": items}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error processing PDF: {str(e)}")
    finally:
        # Clean up the temporary file
        import os
        if os.path.exists(file_path):
            os.remove(file_path)

@app.get("/invoices/", response_model=List[Dict])
async def get_all_invoices():
    try:
        # Connect to MySQL
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Fetch all invoices
        cursor.execute("SELECT * FROM invoices")
        invoices = cursor.fetchall()

        return invoices
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Error fetching invoices: {err}")
    finally:
        # Close the connection
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/invoices/{invoice_id}", response_model=Dict)
async def get_invoice_by_id(invoice_id: int = Path(..., description="The ID of the invoice"), current_user: User = Depends(get_current_user)):
    try:
        # Connect to MySQL
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor(dictionary=True)

        # Fetch invoice by ID
        cursor.execute("SELECT * FROM invoices WHERE id = %s", (invoice_id,))
        invoice = cursor.fetchone()

        if not invoice:
            raise HTTPException(status_code=404, detail="Invoice not found")

        # Fetch items for the invoice
        cursor.execute("SELECT * FROM invoice_items WHERE invoice_id = %s", (invoice_id,))
        items = cursor.fetchall()

        return {"invoice": invoice, "items": items}
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Error fetching invoice: {err}")
    finally:
        # Close the connection
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.put("/invoices/{invoice_id}")
async def update_invoice(invoice_id: int, invoice_update: InvoiceUpdate):
    try:
        # Connect to MySQL
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Build the update query dynamically
        update_fields = []
        update_values = []
        for field, value in invoice_update.dict().items():
            if value is not None:
                update_fields.append(f"{field} = %s")
                update_values.append(value)

        if not update_fields:
            raise HTTPException(status_code=400, detail="No fields to update")

        update_query = f"UPDATE invoices SET {', '.join(update_fields)} WHERE id = %s"
        update_values.append(invoice_id)

        # Execute the update query
        cursor.execute(update_query, update_values)
        connection.commit()

        return {"message": "Invoice updated successfully!"}
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Error updating invoice: {err}")
    finally:
        # Close the connection
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.delete("/invoices/{invoice_id}")
async def delete_invoice(invoice_id: int):
    try:
        # Connect to MySQL
        connection = mysql.connector.connect(**db_config)
        cursor = connection.cursor()

        # Delete the invoice
        cursor.execute("DELETE FROM invoices WHERE id = %s", (invoice_id,))
        connection.commit()

        return {"message": "Invoice deleted successfully!"}
    except mysql.connector.Error as err:
        raise HTTPException(status_code=500, detail=f"Error deleting invoice: {err}")
    finally:
        # Close the connection
        if connection.is_connected():
            cursor.close()
            connection.close()

@app.get("/")
async def root():
    return {"message": "Welcome to the PDF Invoice Extractor API!"}

# Run the FastAPI app
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)