# Quantum Space X — Consignment Store API Integration

## Overview
Link your consignment website to the QSX store checkout. Customers browse on your site, checkout creates an order on QSX, and payment/fulfillment is handled through the QSX platform.

**Base URL:** `https://quantumx.win`

---

## Authentication
All external API calls require your API key in the `X-API-Key` header:

```
X-API-Key: qsx_d61ef3d51b3fd7880ac5d5fa9d572caf0fe281d69e12c127
```

---

## Endpoints

### 1. Get Products
List all available products with prices and images.

**GET** `/api/external/products`

**Response:**
```json
{
  "products": [
    {
      "id": "tesla-model-s",
      "name": "Tesla Model S",
      "price": 79990,
      "image": "https://quantumx.win/images/tesla-model-s.jpg"
    },
    {
      "id": "tesla-model-y",
      "name": "Tesla Model Y",
      "price": 49990,
      "image": "https://quantumx.win/images/tesla-model-y.jpg"
    },
    {
      "id": "tesla-model-3",
      "name": "Tesla Model 3",
      "price": 42990,
      "image": "https://quantumx.win/images/tesla-model-3.jpg"
    },
    {
      "id": "tesla-model-x",
      "name": "Tesla Model X",
      "price": 89990,
      "image": "https://quantumx.win/images/tesla-model-x.jpg"
    },
    {
      "id": "tesla-cybertruck",
      "name": "Tesla Cybertruck",
      "price": 69990,
      "image": "https://quantumx.win/images/tesla-cybertruck.jpg"
    },
    {
      "id": "optimus-bot",
      "name": "Optimus Bot",
      "price": 25000,
      "image": "https://quantumx.win/images/optimus-bot.jpg"
    }
  ],
  "payment_methods": [...],
  "site": "https://quantumx.win"
}
```

---

### 2. Create Checkout Order
Place an order from your consignment site. This creates a QSX user account (if needed), a deposit transaction, and a product order.

**POST** `/api/external/checkout`

**Request Body:**
```json
{
  "product_id": "tesla-model-s",
  "customer_email": "customer@example.com",
  "customer_name": "John Doe",
  "payment_method": "bitcoin",
  "shipping_address": "123 Main St, New York, NY 10001"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `product_id` | ✅ | Product ID from the products list |
| `customer_email` | ✅ | Customer's email (used to find/create QSX account) |
| `customer_name` | Optional | Customer's full name |
| `payment_method` | Optional | Default: `bitcoin`. Options: `bitcoin`, `cashapp`, `paypal`, `zelle`, `wire`, `western-union` |
| `shipping_address` | Optional | Shipping address for the order |

**Response (201):**
```json
{
  "success": true,
  "order": {
    "id": 15,
    "reference": "QSX-A1B2C3",
    "product": "Tesla Model S",
    "price": 79990,
    "status": "pending"
  },
  "deposit": {
    "reference": "QS-YVHYY",
    "amount": 79990,
    "payment_method": "bitcoin",
    "payment_details": {
      "wallet_address": "bc1q04k3fuas4eratzmv9padu9zjf7dwh4xv0s23k6",
      "network": "Bitcoin"
    }
  },
  "checkout_url": "https://quantumx.win/#/dashboard",
  "message": "Order created. Customer should complete payment on Quantum Space X."
}
```

**Flow after checkout:**
1. Show the customer the Bitcoin wallet address (or redirect them to `checkout_url`)
2. Customer sends payment
3. Admin approves on QSX dashboard
4. You can poll the order status endpoint to update your site

---

### 3. Check Order Status
Track the status of an order placed through the external API.

**GET** `/api/external/order/:reference`

**Response:**
```json
{
  "reference": "QSX-A1B2C3",
  "product": "Tesla Model S",
  "price": 79990,
  "quantity": 1,
  "status": "pending",
  "payment_method": "bitcoin",
  "shipping_address": "123 Main St, New York, NY 10001",
  "customer": {
    "username": "johndoe",
    "email": "customer@example.com"
  },
  "created_at": "2026-08-17 00:15:00",
  "updated_at": null
}
```

**Order statuses:**
- `pending` — Awaiting payment
- `deposit_approved` — Payment confirmed, processing order
- `approved` — Order approved by admin, shipping
- `rejected` — Order rejected

---

## Quick Integration Examples

### JavaScript (Node.js / Browser)
```javascript
const QSX_API = 'https://quantumx.win';
const API_KEY = 'qsx_d61ef3d51b3fd7880ac5d5fa9d572caf0fe281d69e12c127';

// Get products
const products = await fetch(`${QSX_API}/api/external/products`, {
  headers: { 'X-API-Key': API_KEY }
}).then(r => r.json());

// Create checkout
const order = await fetch(`${QSX_API}/api/external/checkout`, {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': API_KEY
  },
  body: JSON.stringify({
    product_id: 'tesla-model-s',
    customer_email: 'buyer@example.com',
    customer_name: 'Jane Smith',
    payment_method: 'bitcoin',
    shipping_address: '456 Oak Ave, Los Angeles, CA 90001'
  })
}).then(r => r.json());

// Show Bitcoin wallet to customer
console.log('Send BTC to:', order.deposit.payment_details.wallet_address);
console.log('Amount: $' + order.deposit.amount);

// Check order status later
const status = await fetch(`${QSX_API}/api/external/order/${order.order.reference}`, {
  headers: { 'X-API-Key': API_KEY }
}).then(r => r.json());
```

### Python (requests)
```python
import requests

QSX_API = "https://quantumx.win"
API_KEY = "qsx_d61ef3d51b3fd7880ac5d5fa9d572caf0fe281d69e12c127"
headers = {"X-API-Key": API_KEY}

# Get products
products = requests.get(f"{QSX_API}/api/external/products", headers=headers).json()

# Create checkout
order = requests.post(f"{QSX_API}/api/external/checkout", headers={
    **headers, "Content-Type": "application/json"
}, json={
    "product_id": "tesla-model-y",
    "customer_email": "buyer@example.com",
    "customer_name": "Jane Smith",
    "payment_method": "bitcoin",
    "shipping_address": "789 Pine Rd, Houston, TX 77001"
}).json()

# Check status
status = requests.get(f"{QSX_API}/api/external/order/{order['order']['reference']}", headers=headers).json()
```

### PHP (cURL)
```php
$apiKey = 'qsx_d61ef3d51b3fd7880ac5d5fa9d572caf0fe281d69e12c127';
$baseUrl = 'https://quantumx.win';

// Create checkout
$ch = curl_init("$baseUrl/api/external/checkout");
curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_HTTPHEADER => [
        'Content-Type: application/json',
        "X-API-Key: $apiKey"
    ],
    CURLOPT_POSTFIELDS => json_encode([
        'product_id' => 'tesla-model-3',
        'customer_email' => 'buyer@example.com',
        'customer_name' => 'Jane Smith',
        'payment_method' => 'bitcoin',
        'shipping_address' => '321 Elm Blvd, Chicago, IL 60601'
    ]),
    CURLOPT_RETURNTRANSFER => true
]);
$order = json_decode(curl_exec($ch), true);
curl_close($ch);
```

---

## Bitcoin Payment Wallet
`bc1q04k3fuas4eratzmv9padu9zjf7dwh4xv0s23k6`

All Bitcoin payments go directly to this wallet. For other payment methods, admin will provide details to the customer via inbox message.

---

## Admin API Key Management
- **View key:** Admin Panel → ⚙️ Settings → 🔗 External API Key section
- **Copy key:** Click 📋 Copy button
- **Regenerate key:** Click 🔄 Regenerate (⚠️ invalidates old key immediately)
