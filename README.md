### **1. `requirements.txt`**
This file lists all the Python dependencies required for the project. Create a file named `requirements.txt` in your project root directory and add the following:

```plaintext
fastapi==0.95.2
uvicorn==0.22.0
mysql-connector-python==8.0.33
pdfplumber==0.9.0
python-jose[cryptography]==3.3.0
passlib[bcrypt]==1.7.4
```

---

### **2. `README.md`**
This file provides an overview of your project and instructions for setting it up. Create a file named `README.md` in your project root directory and add the following:

```markdown
# FastAPI Invoice Management System

This is a FastAPI-based backend for managing invoices. It allows users to upload PDF invoices, extract data, and store it in a MySQL database. The API also supports CRUD operations for invoices and authentication using JWT tokens.

## Features
- Upload PDF invoices and extract data.
- Store invoice data in a MySQL database.
- Perform CRUD operations on invoices.
- Secure endpoints using JWT authentication.

## Prerequisites
- Python 3.7 or later
- MySQL database
- Git (for version control)

## Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/benakdeepak/API.git
cd API
```

### 2. Set Up a Virtual Environment
```bash
python -m venv env
env\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Set Up the MySQL Database
1. Create a database named `APIS` in MySQL.
2. Run the following SQL commands to create the required tables:
   ```sql
   USE APIS;

   CREATE TABLE invoices (
    id INT AUTO_INCREMENT PRIMARY KEY,
    invoice_number VARCHAR(50),
    invoice_date VARCHAR(50),
    vendor_name VARCHAR(100),
    sub_total DECIMAL(10, 2),
    discount DECIMAL(10, 2),
    grand_total DECIMAL(10, 2),
    ewaybill_number VARCHAR(50)
);

CREATE TABLE invoice_items (
    id INT AUTO_INCREMENT PRIMARY KEY,
    invoice_id INT,
    description VARCHAR(255),
    hsn_sac VARCHAR(50),
    expiry VARCHAR(50),
    quantity DECIMAL(10, 2),
    deal DECIMAL(10, 2),
    total_quantity DECIMAL(10, 2),
    mrp DECIMAL(10, 2),
    tax DECIMAL(10, 2),
    discount_percent DECIMAL(10, 2),
    amount DECIMAL(10, 2),
    FOREIGN KEY (invoice_id) REFERENCES invoices(id) ON DELETE CASCADE
);
   ```

### 5. Configure the Database Connection
Update the `db_config` in `main.py` with your MySQL credentials:
```python
db_config = {
    "host": "localhost",
    "user": "root",
    "password": "your-mysql-password",
    "database": "APIS"
}
```

### 6. Run the FastAPI Server
```bash
uvicorn main:app --reload
```

The server will start at `http://127.0.0.1:8000`.

### 7. Test the API
- Use **Postman** or **cURL** to test the endpoints.
- Access the interactive API documentation at:
  ```
  http://127.0.0.1:8000/docs
  ```

## API Endpoints
- **POST `/token`**: Get an access token for authentication.
- **POST `/upload-pdf/`**: Upload a PDF invoice and extract data.
- **GET `/invoices/`**: Fetch all invoices.
- **GET `/invoices/{invoice_id}`**: Fetch a single invoice by ID.
- **PUT `/invoices/{invoice_id}`**: Update an invoice.
- **DELETE `/invoices/{invoice_id}`**: Delete an invoice.

## Deployment
To deploy the application, use a production-ready server like **Gunicorn** with **Uvicorn Workers**:
```bash
pip install gunicorn
gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app
```

---

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
```

---

### **3. Steps for GitHub Deployment**

#### **Step 1: Initialize a Git Repository**
1. Navigate to your project directory:
   ```bash
   cd API
   ```
2. Initialize a Git repository:
   ```bash
   git init
   ```

#### **Step 2: Add Files to Git**
1. Add all files to the staging area:
   ```bash
   git add .
   ```
2. Commit the changes:
   ```bash
   git commit -m "Initial commit"
   ```

#### **Step 3: Create a GitHub Repository**
1. Go to [GitHub](https://github.com) and create a new repository.
2. Copy the repository URL (e.g., `https://github.com/benakdeepak/API.git`).

#### **Step 4: Push to GitHub**
1. Add the remote repository:
   ```bash
   git remote add origin https://github.com/benakdeepak/API.git
   ```
2. Push the code to GitHub:
   ```bash
   git push -u origin main
   ```

---

### **4. Deployment to Production**
To deploy your FastAPI application to a production environment, follow these steps:

#### **Step 1: Install Gunicorn**
Install Gunicorn to serve your FastAPI app:
```bash
pip install gunicorn
```

#### **Step 2: Run the App with Gunicorn**
Use Gunicorn with Uvicorn workers to run the app:
```bash
gunicorn -w 4 -k uvicorn.workers.UvicornWorker main:app
```

#### **Step 3: Deploy to a Cloud Platform**
You can deploy your app to platforms like:
- **Heroku**
- **AWS**
- **Google Cloud**
- **DigitalOcean**

For example, to deploy to Heroku:
1. Install the Heroku CLI.
2. Log in to Heroku:
   ```bash
   heroku login
   ```
3. Create a Heroku app:
   ```bash
   heroku create your-app-name
   ```
4. Push your code to Heroku:
   ```bash
   git push heroku main
   ```

---

### **5. Summary**
- The `requirements.txt` file lists all dependencies.
- The `README.md` file provides setup and usage instructions.
- Follow the steps to push your code to GitHub and deploy it to a production environment.

