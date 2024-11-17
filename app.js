const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const multer = require('multer');
const path = require('path');
const http = require('http');
const socketIo = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// MongoDB Setup
mongoose.connect('mongodb://localhost/stockdb', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('Connection error:', err));

// Configure Session with MongoDB for Persistence
app.use(session({
  secret: 'yourSecretKey',  // Replace with a secure secret key
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: 'mongodb://localhost/stockdb',
    collectionName: 'sessions',
    ttl: 24 * 60 * 60
  }),
  cookie: { maxAge: 1000 * 60 * 60 * 24 }
}));

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// File Upload Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, 'uploads/'),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const upload = multer({ storage });

// Models
const UserSchema = new mongoose.Schema({
  username: String,
  password: String,
  role: { type: String, enum: ['Seller', 'Buyer'] }
});
const ProductSchema = new mongoose.Schema({
  name: String,
  price: Number,
  quantity: Number,
  image: String,
  isSaleActive: { type: Boolean, default: true }
});
const OrderSchema = new mongoose.Schema({
  productName: { type: String, required: true },
  quantity: { type: Number, required: true },
  customerName: { type: String, required: true },
  paymentProof: { type: String },
  status: {
      type: String,
      enum: ['Pending', 'Completed', 'Canceled', 'Confirmed', 'Cancelled'], // Add all possible statuses
      default: 'Pending',
  },
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', UserSchema);
const Product = mongoose.model('Product', ProductSchema);
const Order = mongoose.model('Order', OrderSchema);
module.exports = Order;

// Authentication Middleware
function isAuthenticated(req, res, next) {
  if (req.session && req.session.user) return next();
  res.redirect('/login');
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.session.user && req.session.user.role === role) return next();
    res.status(403).send('Access denied');
  };
}

// Serve Login and Register Pages
// Serve the login page (now renamed from admin.html to index.html)
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Serve the admin page (now renamed from index.html to admin.html)
app.get('/admin', isAuthenticated, requireRole('Seller'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Register Route
app.post('/register', async (req, res) => {
  const { username, password, role } = req.body;

  const existingUser = await User.findOne({ username });
  if (existingUser) {
    return res.status(400).json({ message: 'Username already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashedPassword, role });
  await user.save();

  res.status(201).json({ message: 'Registration successful! Please log in.' });
});

// Login Route
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });
  if (!user) {
    return res.status(400).json({ message: 'Username not found' });
  }

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) {
    return res.status(400).json({ message: 'Incorrect password' });
  }

  req.session.user = user;
  res.json({
    message: 'Login successful',
    redirectUrl: user.role === 'Seller' ? '/admin' : '/customer',
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login');
});

// Product Routes (Seller Only)
app.post('/products', isAuthenticated, requireRole('Seller'), upload.single('productImage'), async (req, res) => {
  const { name, price, quantity } = req.body;

  if (!name || !price || !quantity) return res.status(400).json({ message: 'All fields are required' });

  const newProduct = new Product({
    name,
    price,
    quantity,
    image: req.file ? req.file.filename : null
  });
  await newProduct.save();

  res.status(201).json({ message: 'เพิ่มสินค้าใหม่สำเร็จแล้ว', product: newProduct });
});

app.get('/products', async (req, res) => {
  const products = await Product.find();
  res.json(products);
});

app.put('/products/:id/quantity', isAuthenticated, requireRole('Seller'), async (req, res) => {
  const { id } = req.params;
  const { quantity } = req.body;

  const product = await Product.findById(id);
  if (!product) return res.status(404).json({ message: 'Product not found' });

  product.quantity = quantity;
  await product.save();
  res.json({ message: 'อัพเดตจำนวนสินค้าแล้ว', product });
});

app.put('/products/:id/toggle-sale', isAuthenticated, requireRole('Seller'), async (req, res) => {
  const { id } = req.params;
  const { isSaleActive } = req.body;

  const product = await Product.findById(id);
  if (!product) return res.status(404).json({ message: 'Product not found' });

  product.isSaleActive = isSaleActive;
  await product.save();
  res.json({ message: `Product sale status ${isSaleActive ? 'enabled' : 'disabled'}`, product });
});

app.delete('/products/:id', isAuthenticated, requireRole('Seller'), async (req, res) => {
  const { id } = req.params;

  const product = await Product.findByIdAndDelete(id);
  if (!product) return res.status(404).json({ message: 'Product not found' });

  res.json({ message: 'Product deleted successfully' });
});

// Order Route for Creating New Orders
app.post('/order', isAuthenticated, requireRole('Buyer'), upload.single('paymentProof'), async (req, res) => {
  try {
      // Get the logged-in user's username from the session
      const customerName = req.session.user.username; 
      const { selectedProducts } = req.body;
      const products = JSON.parse(selectedProducts);

      // Map each product to an order document with customer information
      const orders = products.map(product => ({
          productName: product.productName,
          quantity: product.quantity,
          customerName, // Use customerName from session to ensure data consistency
          paymentProof: req.file ? req.file.filename : null,
          status: 'Pending' // Optionally add a default order status
      }));

      // Insert orders into the database
      const createdOrders = await Order.insertMany(orders);

      // Emit a new order event to notify other clients (if applicable)
      io.emit('new_order', createdOrders);
      
      res.status(201).json({ message: 'สั่งสินค้าเรียบร้อยแล้ว', orders: createdOrders });
  } catch (error) {
      console.error('Error creating orders:', error);
      res.status(500).json({ message: 'Error placing the order' });
  }
});

app.get('/orders', isAuthenticated, requireRole('Seller'), async (req, res) => {
  const orders = await Order.find();
  res.json(orders);
});

app.put('/order/:id/confirm', isAuthenticated, requireRole('Seller'), async (req, res) => {
  const { id } = req.params;
  const order = await Order.findById(id);
  if (!order) return res.status(404).json({ message: 'Order not found' });

  order.status = 'Confirmed';
  await order.save();
  io.emit('order_updated', order);
  res.json({ message: 'ยืนยันออเดอร์แล้ว', order });
});

app.post('/confirm-order', isAuthenticated, requireRole('Seller'), async (req, res) => {
  try {
      const { orderId } = req.body;

      // Find the order by ID
      const order = await Order.findById(orderId);
      if (!order) {
          return res.status(404).json({ message: 'Order not found' });
      }

      // Update the order status to 'Confirmed'
      order.status = 'Confirmed';
      await order.save();

      // Emit a socket event to notify buyers
      io.emit('order_updated', { orderId: order._id, status: 'Confirmed' });

      res.status(200).json({ message: 'Order confirmed successfully' });
  } catch (error) {
      console.error('Error confirming order:', error);
      res.status(500).json({ message: 'Error confirming order' });
  }
});

app.put('/order/:id/complete', isAuthenticated, requireRole('Seller'), async (req, res) => {
  const { id } = req.params;
  const order = await Order.findById(id);
  if (!order) return res.status(404).json({ message: 'Order not found' });

  const product = await Product.findOne({ name: order.productName });
  if (!product) return res.status(404).json({ message: 'Product not found' });
  if (product.quantity < order.quantity) return res.status(400).json({ message: 'Not enough stock' });

  product.quantity -= order.quantity;
  await product.save();

  order.status = 'Completed';
  await order.save();
  io.emit('order_updated', order);
  res.json({ message: 'สำเร็จออเดอร์เรียบร้อยแล้ว จำนวนสต็อคทำการอัพเดต', order });
});

app.put('/order/:id/cancel', isAuthenticated, requireRole('Seller'), async (req, res) => {
  const { id } = req.params;
  const order = await Order.findById(id);
  if (!order) return res.status(404).json({ message: 'Order not found' });

  order.status = 'Canceled';
  await order.save();
  io.emit('order_updated', order);
  res.json({ message: 'ยกเลิกออเดอร์', order });
});

app.delete('/order/:id', isAuthenticated, requireRole('Seller'), async (req, res) => {
  const { id } = req.params;
  const order = await Order.findByIdAndDelete(id);
  if (!order) return res.status(404).json({ message: 'Order not found' });

  io.emit('order_deleted', { _id: id });
  res.json({ message: 'Order deleted' });
});

// Cancel Order Route
app.post('/cancel-order', isAuthenticated, requireRole('Buyer'), async (req, res) => {
  try {
      const { orderId } = req.body;

      // Find the order by ID and check if it belongs to the logged-in user
      const order = await Order.findOne({ _id: orderId, customerName: req.session.user.username });

      if (!order) {
          return res.status(404).json({ message: 'Order not found or not authorized to cancel.' });
      }

      if (order.status === 'Completed') {
          return res.status(400).json({ message: 'Completed orders cannot be canceled.' });
      }

      // Update the order status to 'Canceled'
      order.status = 'Canceled';
      await order.save();

      res.status(200).json({ message: 'Order canceled successfully.', order });
  } catch (error) {
      console.error('Error canceling order:', error);
      res.status(500).json({ message: 'Error canceling order.' });
  }
});

// Order History Route for Customers
app.get('/order-history', isAuthenticated, requireRole('Buyer'), async (req, res) => {
  try {
      const customerName = req.session.user.username; // Retrieves the customer's username from session
      const orders = await Order.find({ customerName }); // Finds orders based on customer name

      res.json(orders); // Sends the list of orders to the client
  } catch (error) {
      console.error('Error fetching order history:', error);
      res.status(500).json({ message: 'Error fetching order history' });
  }
});

// Role-Specific Page Routing
app.get('/index', isAuthenticated, requireRole('Seller'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/customer', isAuthenticated, requireRole('Buyer'), (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'customer.html'));
});

// Real-Time Notifications
io.on('connection', (socket) => {
  console.log('A user connected');
  socket.on('disconnect', () => console.log('User disconnected'));
});

// Start the Server
server.listen(3000, () => {
  console.log('Server is running on port 3000');
});
