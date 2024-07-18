const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const session = require('express-session');
require('dotenv').config();

const app = express();
const PORT = 3000 || null;

const pool = new Pool({
    user: 'postgres.zhbravqsvtqypxmykvdf',
    host: 'aws-0-ap-south-1.pooler.supabase.com',
    database: 'postgres',
    password: 'Kaviswar@123',
    port: 6543
});

app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

const secretKey = "97b34701a945e7d7717fbf4d678f280766a6a64dc7662d7f68318f13d0fe01c085ab970eb17daa8138457f3dac983cd92a6f8e770462ef5ccbfd4d39d9a61bc4";
app.use(session({
    secret: secretKey,
    resave: false,
    saveUninitialized: true
}));

const createTokens = (req, res, user) => {
    const username = user.username;
    const accessToken = jwt.sign({ username: username }, secretKey, { expiresIn: '1h' });
    req.session.jwtToken = accessToken;
    return accessToken;
};

const validateToken = (req, res, next) => {
    try {
        if (!req.headers.authorization) {
            return res.redirect('#');
        }

        const accessToken = req.headers.authorization.split(' ')[1];

        jwt.verify(accessToken, secretKey, (err, decoded) => {
            if (err) {
                console.error('auth error', err.message);
                return res.status(401).json({ error: 'unauthorized' });
            } else {
                req.user = decoded;
                next();
            }
        });
    } catch (err) {
        console.error('auth error', err.message);
        res.status(500).send('Internal Server Error');
    }
};

app.post('/api/decodeToken', [validateToken, async (req, res) => {
    console.log('api decode requested');
    try {
        const { token } = req.body;
        console.log(token);
        const decodedToken = jwt.verify(token, secretKey);
        const { username } = decodedToken;

        try {
            const query = 'SELECT username FROM users WHERE username = $1';
            const values = [username];
            const result = await pool.query(query, values);

            if (result.rows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            const userData = result.rows[0];
            console.log('decoded token');

            res.status(200).json(userData);
        } catch (error) {
            console.error('Error querying database:', error.message);
            res.status(500).json({ error: 'Internal server error' });
        }
    } catch (error) {
        console.error('Error decoding token:', error.message);
        res.status(400).json({ error: 'Failed to decode token' });
    }
}]);

app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;

    try {
        const checkQuery = 'SELECT * FROM Users WHERE username = $1';
        const checkResult = await pool.query(checkQuery, [username]);

        if (checkResult.rows.length > 0) {
            return res.status(400).json({
                status: 'error',
                message: 'Username already taken',
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'INSERT INTO Users (username, password, email, team_id, current_projects, past_projects) VALUES ($1, $2, $3, NULL, 0, 0) RETURNING *';
        const values = [username, hashedPassword, email];
        const result = await pool.query(query, values);

        res.status(201).json({
            status: 'success',
            message: 'Registration successful',
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            status: 'error',
            message: 'Internal Server Error',
        });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const query = 'SELECT * FROM Users WHERE username = $1';
        const values = [username];
        const result = await pool.query(query, values);

        if (result.rows.length === 0) {
            return res.status(400).json({
                status: 'error',
                message: 'Invalid username or password',
            });
        }

        const user = result.rows[0];
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(400).json({
                status: 'error',
                message: 'Invalid username or password',
            });
        }

        const token = createTokens(req, res, user);
        res.status(200).json({
            status: 'success',
            message: 'Login successful',
            token: token,
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            status: 'error',
            message: 'Internal Server Error',
        });
    }
});

app.post('/reset-password', async (req, res) => {
    const { username, email, newPassword } = req.body;

    try {
        const query = 'SELECT * FROM Users WHERE username = $1 AND email = $2';
        const values = [username, email];
        const result = await pool.query(query, values);

        if (result.rows.length === 0) {
            return res.status(400).json({
                status: 'error',
                message: 'Invalid username or email',
            });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        const updateQuery = 'UPDATE Users SET password = $1 WHERE username = $2';
        const updateValues = [hashedPassword, username];
        await pool.query(updateQuery, updateValues);

        res.status(200).json({
            status: 'success',
            message: 'Password reset successful',
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            status: 'error',
            message: 'Internal Server Error',
        });
    }
});

app.post('/api/userProfile', [validateToken, async (req, res) => {
    const username = req.body.username;
    try {
        const userResult = await pool.query('SELECT * FROM UserProfile WHERE username = $1', [username]);
        const taskResult = await pool.query('SELECT status, COUNT(*) as count FROM Tasks WHERE username = $1 GROUP BY status', [username]);
        const userTableResult = await pool.query('SELECT current_projects, past_projects FROM users WHERE username = $1', [username]);

        const user = userResult.rows[0];
        const userTable = userTableResult.rows[0];
        const tasks = {
            pending: 0,
            in_progress: 0,
            completed: 0,
        };

        taskResult.rows.forEach(row => {
            if (row.status === 'pending') tasks.pending = parseInt(row.count);
            if (row.status === 'in_progress') tasks.in_progress = parseInt(row.count);
            if (row.status === 'completed') tasks.completed = parseInt(row.count);
        });

        res.json({
            username: user.username,
            first_name: user.first_name,
            last_name: user.last_name,
            bio: user.bio,
            dob: user.dob,
            tasks: tasks,
            current_projects: userTable.current_projects,
            past_projects: userTable.past_projects
        });
    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).send('Server error');
    }
}]);

app.post('/api/createTeam', [validateToken, async (req, res) => {
    const { team_name, team_leader } = req.body;

    try {
        const query = 'INSERT INTO teams (team_name, team_leader) VALUES ($1, $2) RETURNING *';
        const values = [team_name, team_leader];
        const result = await pool.query(query, values);

        res.status(201).json({
            status: 'success',
            message: 'Team created successfully',
            team: result.rows[0],
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            status: 'error',
            message: 'Internal Server Error',
        });
    }
}]);

app.post('/api/sendJoinRequest', [validateToken, async (req, res) => {
    const { username, team_id } = req.body;

    try {
        const query = 'INSERT INTO requests (username, team_id, status) VALUES ($1, $2, $3) RETURNING *';
        const values = [username, team_id, 'pending'];
        const result = await pool.query(query, values);

        res.status(201).json({
            status: 'success',
            message: 'Join request sent successfully',
            request: result.rows[0],
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            status: 'error',
            message: 'Internal Server Error',
        });
    }
}]);

app.post('/api/acceptJoinRequest', [validateToken, async (req, res) => {
    const { request_id } = req.body;

    try {
        const query = 'UPDATE requests SET status = $1 WHERE request_id = $2 RETURNING *';
        const values = ['accepted', request_id];
        const result = await pool.query(query, values);

        const { username, team_id } = result.rows[0];
        await pool.query('UPDATE users SET team_id = $1 WHERE username = $2', [team_id, username]);

        res.status(200).json({
            status: 'success',
            message: 'Join request accepted successfully',
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            status: 'error',
            message: 'Internal Server Error',
        });
    }
}]);

app.post('/api/assignTask', [validateToken, async (req, res) => {
    const { team_id, assigned_to, description, status, priority, category, due_date, due_time } = req.body;

    try {
        const query = 'INSERT INTO tasks (team_id, assigned_to, description, status, priority, category, due_date, due_time) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *';
        const values = [team_id, assigned_to, description, status, priority, category, due_date, due_time];
        const result = await pool.query(query, values);

        res.status(201).json({
            status: 'success',
            message: 'Task assigned successfully',
            task: result.rows[0],
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            status: 'error',
            message: 'Internal Server Error',
        });
    }
}]);

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
