Here’s a **detailed step-by-step guide** for testing the authentication flow in your FastAPI application using **Postman** and **cURL**. This includes:

1. **Getting an Access Token** (using `/token` endpoint).
2. **Using the Token to Access Protected Endpoints**.

---

### **1. Prerequisites**
- Ensure your FastAPI server is running:
  ```bash
  uvicorn main:app --reload
  ```
- Install **Postman** (if you want to use it for testing).
- Ensure you have `curl` installed (available by default on macOS/Linux; for Windows, use Git Bash or WSL).

---

### **2. Authentication Flow**
The authentication flow involves the following steps:
1. **Get an Access Token**: Send a `POST` request to the `/token` endpoint with a username and password.
2. **Use the Token**: Include the token in the `Authorization` header to access protected endpoints.

---

### **3. Step-by-Step Guide**

#### **Step 1: Get an Access Token**
You need to send a `POST` request to the `/token` endpoint with the username and password.

##### **Using Postman**
1. Open Postman.
2. Set the request type to `POST`.
3. Enter the URL:
   ```
   http://127.0.0.1:8000/token
   ```
4. Go to the **Headers** tab and add:
   - Key: `accept`, Value: `application/json`
   - Key: `Content-Type`, Value: `application/x-www-form-urlencoded`
5. Go to the **Body** tab, select `x-www-form-urlencoded`, and add:
   - Key: `username`, Value: `admin`
   - Key: `password`, Value: `adminpassword`
6. Click **Send**.

##### **Using cURL**
Run the following command in your terminal:
```bash
curl -X POST "http://127.0.0.1:8000/token" \
-H "accept: application/json" \
-H "Content-Type: application/x-www-form-urlencoded" \
-d "username=admin&password=adminpassword"
```

##### **Expected Response**
If the credentials are correct, you will receive a response like this:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

Save the `access_token` for the next step.

---

#### **Step 2: Use the Token to Access Protected Endpoints**
Now that you have the token, you can use it to access protected endpoints (e.g., `/invoices/`).

##### **Using Postman**
1. Open a new request in Postman.
2. Set the request type to `GET`.
3. Enter the URL:
   ```
   http://127.0.0.1:8000/invoices/
   ```
4. Go to the **Headers** tab and add:
   - Key: `Authorization`, Value: `Bearer <access_token>`
     Replace `<access_token>` with the token you received in Step 1.
5. Click **Send**.

##### **Using cURL**
Run the following command in your terminal:
```bash
curl -X GET "http://127.0.0.1:8000/invoices/" \
-H "accept: application/json" \
-H "Authorization: Bearer <access_token>"
```
Replace `<access_token>` with the token you received in Step 1.

##### **Expected Response**
If the token is valid, you will receive a response like this:
```json
[
  {
    "id": 1,
    "invoice_number": "2503181308A7",
    "invoice_date": "March 22, 2025",
    "vendor_name": "GreenLeaf Organics Pvt. Ltd.",
    "sub_total": 27000.0,
    "discount": 1350.0,
    "grand_total": 26932.5,
    "ewaybill_number": null
  }
]
```

---

#### **Step 3: Test Other Protected Endpoints**
You can use the same token to access other protected endpoints, such as:
- **GET `/invoices/{invoice_id}`**: Fetch a single invoice by ID.
- **PUT `/invoices/{invoice_id}`**: Update an invoice.
- **DELETE `/invoices/{invoice_id}`**: Delete an invoice.

##### **Example: Get Invoice by ID**
###### **Using Postman**
1. Set the request type to `GET`.
2. Enter the URL:
   ```
   http://127.0.0.1:8000/invoices/1
   ```
3. Add the `Authorization` header with the token.
4. Click **Send**.

###### **Using cURL**
```bash
curl -X GET "http://127.0.0.1:8000/invoices/1" \
-H "accept: application/json" \
-H "Authorization: Bearer <access_token>"
```

##### **Example: Update Invoice**
###### **Using Postman**
1. Set the request type to `PUT`.
2. Enter the URL:
   ```
   http://127.0.0.1:8000/invoices/1
   ```
3. Add the `Authorization` header with the token.
4. Go to the **Body** tab, select `raw`, and enter the JSON data:
   ```json
   {
     "invoice_number": "NEW123"
   }
   ```
5. Click **Send**.

###### **Using cURL**
```bash
curl -X PUT "http://127.0.0.1:8000/invoices/1" \
-H "accept: application/json" \
-H "Authorization: Bearer <access_token>" \
-H "Content-Type: application/json" \
-d '{"invoice_number": "NEW123"}'
```

---

### **4. Summary of Steps**
1. **Get an Access Token**:
   - Send a `POST` request to `/token` with `username` and `password`.
   - Save the `access_token` from the response.

2. **Use the Token**:
   - Include the token in the `Authorization` header for protected endpoints.
   - Example: `Authorization: Bearer <access_token>`

3. **Test Protected Endpoints**:
   - Use the token to access `/invoices/`, `/invoices/{invoice_id}`, etc.

---

### **5. Troubleshooting**
- **401 Unauthorized**: Ensure the token is valid and included in the `Authorization` header.
- **422 Validation Error**: Ensure the request body is formatted correctly (e.g., `x-www-form-urlencoded` for `/token`).
- **500 Internal Server Error**: Check the FastAPI server logs for details.

---

Let me know if you need further assistance!