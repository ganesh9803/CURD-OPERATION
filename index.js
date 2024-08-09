const express = require('express');
const { open } = require('sqlite');
const sqlite3 = require('sqlite3');
const path = require('path');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const databasePath = path.join(__dirname, 'Products.DB');
const app = express();
app.use(express.json());

let database = null;

const initializeDbAndServer = async () => {
  try {
    database = await open({
      filename: databasePath,
      driver: sqlite3.Database,
    });

    app.listen(3000, () =>
      console.log('Server Running at http://localhost:3000/'),
    );
  } catch (error) {
    console.log(`DB Error: ${error.message}`);
    process.exit(1);
  }
};

initializeDbAndServer();

// new user registration
const validatePassword = (password) => {
  return password.length > 4;
};

app.post('/register', async (request, response) => {
  const { username, email, password, role } = request.body;
  console.log('Received data:', { username, email, password, role });
  const hashedPassword = await bcrypt.hash(password, 10);
  const selectUserQuery = `SELECT * FROM users WHERE username = '${username}';`;
  const databaseUser = await database.get(selectUserQuery);

  if (databaseUser === undefined) {
    const createUserQuery = `
      INSERT INTO
       users (username, email, password, role)
      VALUES
       (
        '${username}',
        '${email}',
        '${hashedPassword}',
        '${role}' 
       );`;

    if (validatePassword(password)) {
      await database.run(createUserQuery);
      response.send('User created successfully');
    } else {
      response.status(400);
      response.send('Password is too short');
    }
  } else {
    response.status(400);
    response.send('User already exists');
  }
});

// user login
app.post('/login', async (request, response) => {
  const { username, password } = request.body;
  const selectUserQuery = `SELECT * FROM users WHERE username = '${username}'`;
  const dbUser = await database.get(selectUserQuery);
  if (dbUser === undefined) {
    response.status(400);
    response.send('Invalid User');
  } else {
    const isPasswordMatched = await bcrypt.compare(password, dbUser.password);
    if (isPasswordMatched === true) {
      response.send('Login Success!');
    } else {
      response.status(400);
      response.send('Invalid Password');
    }
  }
});

// generating jwt token
app.post('/login_token', async (request, response) => {
  const { username, password } = request.body;
  const selectUserQuery = `SELECT * FROM users WHERE username = '${username}'`;
  const dbUser = await database.get(selectUserQuery);
  if (dbUser === undefined) {
    response.status(400);
    response.send('Invalid User');
  } else {
    const isPasswordMatched = await bcrypt.compare(password, dbUser.password);
    if (isPasswordMatched === true) {
      const payload = {
        username: username,
        role: dbUser.role, // Include the user's role
      };
      const jwtToken = jwt.sign(payload, 'MY_SECRET_TOKEN');
      response.send({ jwtToken });
    } else {
      response.status(400);
      response.send('Invalid Password');
    }
  }
});

// Middleware to authenticate token
const authenticateToken = (request, response, next) => {
  const authHeader = request.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    return response.status(400).send('Token not provided');
  }

  jwt.verify(token, 'MY_SECRET_TOKEN', (err, user) => {
    if (err) return response.status(403).send('Invalid Token');
    request.user = user;
    next();
  });
};

// Role-based authorization middleware
const authorizeRole = (...allowedRoles) => {
    return (request, response, next) => {
      const userRole = request.user.role;
      if (!allowedRoles.includes(userRole)) {
        return response.status(403).send("Access Denied");
      }
      next();
    };
  };
  

// CREATE Product - Admin Only
app.post("/products/create", authenticateToken, authorizeRole('admin'), async (request, response) => {
    const { title, description, inventory_count } = request.body;
    const createProductQuery = `
      INSERT INTO products (title, description, inventory_count)
      VALUES ('${title}', '${description}', ${inventory_count});
    `;
    await database.run(createProductQuery);
    response.send("Product Created Successfully");
  });
  
  // READ Products - Admin or Manager
  app.get("/products", authenticateToken, authorizeRole('admin', 'manager'), async (request, response) => {
    const getProductsQuery = `SELECT * FROM products;`;
    const products = await database.all(getProductsQuery);
    response.send(products);
  });
  
  // UPDATE Product - Admin or Manager
  app.put("/products/:productId", authenticateToken, authorizeRole('admin', 'manager'), async (request, response) => {
    const { productId } = request.params;
    const { title, description, inventory_count } = request.body;
    
    // Ensure all require fields are provided
    if (!title || !description || inventory_count === undefined) {
        return response.status(400).send("Missing required fields");
    }
    
    const updateProductQuery = `
      UPDATE products
      SET title = '${title}', description = '${description}', inventory_count = ${inventory_count}
      WHERE id = ${productId};
    `;

    try {
        await database.run(updateProductQuery);
        response.send("Product Updated Successfully");
    } catch (error) {
        response.status(500).send("Error updating product")
    }
  });
  
  // DELETE Product - Admin Only
  app.delete("/products/:productId", authenticateToken, authorizeRole('admin'), async (request, response) => {
    const { productId } = request.params;
    const deleteProductQuery = `DELETE FROM products WHERE id = ${productId};`;
    await database.run(deleteProductQuery);
    response.send("Product Deleted Successfully");
  });
