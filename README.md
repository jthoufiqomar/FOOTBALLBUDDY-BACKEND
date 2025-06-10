# FOOTBALLBUDDY Blog Backend

## MySQL Setup
1. Log in to your MySQL server and run:

```sql
CREATE DATABASE footballbuddy_blog;
USE footballbuddy_blog;
CREATE TABLE posts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  content TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

2. Update `.env` with your MySQL username and password.

## Running the Backend
1. Install dependencies (if not done):
   ```powershell
   npm install
   ```
2. Start the server:
   ```powershell
   node index.js
   ```

The backend will run on `http://localhost:3001` by default.

## API Endpoints
- `GET    /api/posts`         - List all posts
- `GET    /api/posts/:id`     - Get a single post
- `POST   /api/posts`         - Create a new post (JSON: { title, content })
- `PUT    /api/posts/:id`     - Update a post (JSON: { title, content })
- `DELETE /api/posts/:id`     - Delete a post

## Connecting Your Frontend
- Use `fetch` or any HTTP client to call the above endpoints from your frontend (e.g., footballbuddy.xyz).
- If your frontend is hosted on a different domain, CORS is enabled by default.
- Example fetch from frontend:

```js
fetch('http://localhost:3001/api/posts')
  .then(res => res.json())
  .then(data => console.log(data));
```

Replace `localhost:3001` with your backend server's public IP or domain when deploying.
