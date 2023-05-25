import express from 'express';
import cors from 'cors';
import userRoutes from './routes/UserRoutes.js';
const PORT = process.env.PORT || 5100;
const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* Routes */
app.use('/api/users', userRoutes);

/* Catch all route */
app.use('*', (req, res) => {
	res.status(404).json({ error: 'Route not found' });
});

app.listen(PORT, () => {
	console.log(`Server listening on port ${PORT}`);
});
