// Required packages
const express = require('express');
const app = express();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Sequelize, DataTypes } = require('sequelize');
const sequelize = new Sequelize('sqlite::memory:'); // Use appropriate database URI
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// Models
const Product = sequelize.define('Product', {
    name: { type: DataTypes.STRING, allowNull: false },
    category: { type: DataTypes.STRING, allowNull: false },
    price: { type: DataTypes.FLOAT, allowNull: false },
    prod_img: { type: DataTypes.STRING }
});

const User = sequelize.define('User', {
    username: { type: DataTypes.STRING, unique: true, allowNull: false },
    password: { type: DataTypes.STRING, allowNull: false },
    email: { type: DataTypes.STRING, unique: true, allowNull: false },
    role: { type: DataTypes.STRING, defaultValue: 'customer' }
});

const Order = sequelize.define('Order', {
    order_status: { type: DataTypes.STRING, allowNull: false },
    delivery_address: { type: DataTypes.STRING, allowNull: false },
    delivery_partner: { type: DataTypes.STRING, allowNull: true }
});

const Cart = sequelize.define('Cart', {
    user_id: { type: DataTypes.INTEGER, allowNull: false },
    product_id: { type: DataTypes.INTEGER, allowNull: false },
    quantity: { type: DataTypes.INTEGER, defaultValue: 1 }
});

// Helper functions
const createToken = (user) => jwt.sign({ userId: user.id, role: user.role }, 'secret_key', { expiresIn: '1h' });

// Middleware for admin authentication
function authenticateAdmin(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ msg: "Access token missing" });
    jwt.verify(token, 'secret_key', (err, decoded) => {
        if (err || decoded.role !== 'admin') return res.status(403).json({ msg: "Unauthorized access" });
        req.user = decoded;
        next();
    });
}

// Middleware for user authentication
function authenticateUser(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ msg: "Access token missing" });
    jwt.verify(token, 'secret_key', (err, decoded) => {
        if (err) return res.status(403).json({ msg: "Unauthorized access" });
        req.user = decoded;
        next();
    });
}

// Routes

// 1. User Registration
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const newUser = await User.create({ username, password: hashedPassword, email });
        res.status(201).json({ msg: "User registered successfully" });
    } catch (error) {
        res.status(400).json({ msg: "Error registering user", error: error.message });
    }
});

// 2. User Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ where: { username } });
    if (user && await bcrypt.compare(password, user.password)) {
        const token = createToken(user);
        res.json({ access_token: token });
    } else {
        res.status(401).json({ msg: "Invalid credentials" });
    }
});

// 3. Admin Login
app.post('/admin/login', async (req, res) => {
    const { username, password } = req.body;
    const admin = await User.findOne({ where: { username, role: 'admin' } });
    if (admin && await bcrypt.compare(password, admin.password)) {
        const token = createToken(admin);
        res.json({ access_token: token });
    } else {
        res.status(401).json({ msg: "Invalid admin credentials" });
    }
});

// 4. Add Product (Admin only)
app.post('/product', authenticateAdmin, async (req, res) => {
    try {
        const product = await Product.create(req.body);
        res.status(201).json({ msg: "Product added successfully", product });
    } catch (error) {
        res.status(400).json({ msg: "Error adding product", error: error.message });
    }
});

// 5. Update Product (Admin only)
app.put('/product/:id', authenticateAdmin, async (req, res) => {
    try {
        const product = await Product.findByPk(req.params.id);
        if (!product) return res.status(404).json({ msg: "Product not found" });
        await product.update(req.body);
        res.json({ msg: "Product updated successfully", product });
    } catch (error) {
        res.status(400).json({ msg: "Error updating product", error: error.message });
    }
});

// 6. Delete Product (Admin only)
app.delete('/product/:id', authenticateAdmin, async (req, res) => {
    try {
        const product = await Product.findByPk(req.params.id);
        if (!product) return res.status(404).json({ msg: "Product not found" });
        await product.destroy();
        res.json({ msg: "Product deleted successfully" });
    } catch (error) {
        res.status(400).json({ msg: "Error deleting product", error: error.message });
    }
});

// 7. Get Products by Category
app.get('/products/:category', async (req, res) => {
    const products = await Product.findAll({ where: { category: req.params.category } });
    if (products.length === 0) return res.status(404).json({ msg: "No products found in this category" });
    res.json(products);
});

// 8. Add Product to Cart
app.post('/cart', authenticateUser, async (req, res) => {
    const userId = req.user.userId;
    const { product_id, quantity } = req.body;
    try {
        const cartItem = await Cart.create({ user_id: userId, product_id, quantity });
        res.status(201).json({ msg: "Product added to cart", cartItem });
    } catch (error) {
        res.status(400).json({ msg: "Error adding to cart", error: error.message });
    }
});

// 9. Place Order for Cart
app.post('/order', authenticateUser, async (req, res) => {
    const userId = req.user.userId;
    const { delivery_address } = req.body;

    try {
        const cartItems = await Cart.findAll({ where: { user_id: userId } });
        if (!cartItems.length) return res.status(400).json({ msg: "Cart is empty" });

        for (let item of cartItems) {
            await Order.create({
                order_status: 'Pending',
                delivery_address,
                delivery_partner: "Not assigned"
            });
        }
        await Cart.destroy({ where: { user_id: userId } });
        res.status(201).json({ msg: "Order placed successfully" });
    } catch (error) {
        res.status(400).json({ msg: "Error placing order", error: error.message });
    }
});

// 10. Update Order Status (Admin only)
app.put('/order/:id/status', authenticateAdmin, async (req, res) => {
    try {
        const order = await Order.findByPk(req.params.id);
        if (!order) return res.status(404).json({ msg: "Order not found" });
        order.order_status = req.body.order_status || order.order_status;
        await order.save();
        res.json({ msg: "Order status updated successfully", order });
    } catch (error) {
        res.status(400).json({ msg: "Error updating order status", error: error.message });
    }
});

// 11. Assign Delivery Partner (Admin only)
app.put('/order/:id/assign-partner', authenticateAdmin, async (req, res) => {
    try {
        const order = await Order.findByPk(req.params.id);
        if (!order) return res.status(404).json({ msg: "Order not found" });
        order.delivery_partner = req.body.delivery_partner || order.delivery_partner;
        await order.save();
        res.json({ msg: "Delivery partner assigned successfully", order });
    } catch (error) {
        res.status(400).json({ msg: "Error assigning delivery partner", error: error.message });
    }
});
const path = require('path');

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, '.')));

// Route for home.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Sync database and start server
sequelize.sync({ force: true }).then(() => {
    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
    });
});
