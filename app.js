const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const jwt=require('jsonwebtoken')
const session=require('express-session')
require('dotenv').config();

const app = express();
const PORT = 3000|| null;

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
}))

const createTokens = (req, res, user) => {
    const username = user.username;
    const accessToken = jwt.sign({
        username: username
    }, secretKey, { expiresIn: '1h' });
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

//decoding the token
app.post('/api/decodeToken',[validateToken, async (req, res) => {
    console.log('api decode requested');
    try {
        // Extract the token from the request body
        const { token } = req.body;
    
        console.log(token);

        // Verify and decode the token
        const decodedToken = jwt.verify(token, secretKey);
        
        // Extract username from decoded token
        const { username } = decodedToken;

        try {
            // Query the database to retrieve user data based on username
            const query = 'SELECT username FROM users WHERE username = $1';
            const values = [username];
            const result = await pool.query(query, values);

            // Check if user exists in the database
            if (result.rows.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            // Get the user data from the query results
            const userData = result.rows[0];
            console.log('decoded token');

            // Send user data back to the client
            res.status(200).json(userData);
        } catch (error) {
            console.error('Error querying database:', error.message);
            res.status(500).json({ error: 'Internal server error' });
        }
    } catch (error) {
        // Handle any errors, such as token validation failure
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
        const query = 'INSERT INTO Users (username, password, email) VALUES ($1, $2, $3) RETURNING *';
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
        const isPasswordValid = await bcrypt.compare(password, user.password);

        if (!isPasswordValid) {
            return res.status(400).json({
                status: 'error',
                message: 'Invalid username or password',
            });
        }

        const token = createTokens(req, res, user);

        // Check if the user exists in the UserProfile table
        const profileQuery = 'SELECT * FROM UserProfile WHERE username = $1';
        const profileResult = await pool.query(profileQuery, values);

        const profileExists = profileResult.rows.length > 0 ? 1 : 0;

        res.json({
            isvalid: true,
            token,
            profileExists
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            status: 'error',
            message: 'Internal Server Error',
        });
    }
});



app.post('/api/addprofile', [validateToken, async (req, res) => {
    const { username, first_name, last_name, date_of_birth, bio } = req.body;
    console.log(req.body);

    if (!username || !first_name || !last_name || !date_of_birth || !bio) {
        return res.status(400).json({
            status: 'error',
            message: 'Missing required fields',
        });
    }

    try {
        console.log("1");
        const query = `
            INSERT INTO UserProfile (username, first_name, last_name, dob, bio)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (username) DO UPDATE
            SET first_name = $2, last_name = $3, dob = $4, bio = $5
            RETURNING *;
        `;
        const values = [username, first_name, last_name, date_of_birth, bio];
        const result = await pool.query(query, values);
        console.log("2");

        if (result.rows.length === 0) {
            return res.status(400).json({
                status: 'error',
                message: 'Failed to update profile',
            });
        }

        console.log("3");

        res.status(200).json({
            status: 'success',
            message: 'Profile updated successfully',
            profile: result.rows[0],
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            status: 'error',
            message: 'Internal Server Error',
        });
    }
}]);



// Route to handle password reset
app.post('/reset-password', async (req, res) => {
    const { username, email, newPassword } = req.body;

    // Find user by username and email
    const user = users.find(u => u.username === username && u.email === email);

    if (!user) {
        return res.status(400).json({
            status: 'error',
            message: 'Username and/or email not found',
        });
    }

    try {
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword; // Update the user's password

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





// Get user profile endpoint
app.post('/api/userProfile',[validateToken, async (req, res) => {
    const username = req.body.username;
    try {
        const userResult = await pool.query('SELECT * FROM UserProfile WHERE username = $1', [username]);
        const taskResult = await pool.query('SELECT status, COUNT(*) as count FROM Tasks WHERE username = $1 GROUP BY status', [username]);

        const user = userResult.rows[0];
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
        });
    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).send('Server error');
    }
}]);

// Update user profile endpoint
app.post('/api/updateUserProfile', validateToken, async (req, res) => {
    const { first_name, last_name, bio, dob } = req.body;
    const username = req.user.username; // Assuming the username is stored in the token

    try {
        await pool.query(
            'UPDATE UserProfile SET first_name = $1, last_name = $2, bio = $3, dob = $4 WHERE username = $5',
            [first_name, last_name, bio, dob, username]
        );
        res.status(200).send('Profile updated successfully');
    } catch (error) {
        console.error('Error updating user profile:', error);
        res.status(500).send('Server error');
    }
});

// Endpoint to handle task creation
app.post('/api/tasks',[validateToken, async (req, res) => {
    const { username, description, status, priority, category, due_date, due_time } = req.body;
  
    try {
      const client = await pool.connect();
      const result = await client.query(
        'INSERT INTO tasks (username, description, status, priority, category, due_date, due_time) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *',
        [username, description, status, priority, category, due_date, due_time]
      );
      client.release();
      
      res.status(201).json(result.rows[0]);
    } catch (error) {
      console.error('Error executing query', error);
      res.status(500).json({ message: 'Failed to create task' });
    }
  }]);

 // Fetch tasks endpoint
app.post('/api/tasks/view', [validateToken, async (req, res) => {
    const { username } = req.body;
    console.log(`Fetching tasks for username: ${username}`);
    
    try {
        const result = await pool.query('SELECT * FROM tasks WHERE username = $1', [username]);
        console.log(`Fetched tasks:`, result.rows);
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching tasks:', error.message);
        res.status(500).json({ message: 'Failed to fetch tasks', error: error.message });
    }
}]);

// Update task endpoint
app.put('/api/tasks/update', [validateToken, async (req, res) => {
    const { taskId, username, description, status, priority, category, due_date, due_time } = req.body;
    try {
        const result = await pool.query(
            'UPDATE tasks SET description = $1, status = $2, priority = $3, category = $4, due_date = $5, due_time = $6 WHERE task_id = $7 AND username = $8',
            [description, status, priority, category, new Date(due_date), due_time, taskId, username]
        );

        if (result.rowCount > 0) {
            res.json({ message: 'Task updated successfully' });
        } else {
            res.status(404).json({ message: 'Task not found' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Failed to update task', error: error.message });
    }
}]);

// Delete task endpoint
app.delete('/api/tasks/deleteTask', [validateToken, async (req, res) => {
    const { taskId, username } = req.body;
    try {
        const result = await pool.query('DELETE FROM tasks WHERE task_id = $1 AND username = $2', [taskId, username]);
        if (result.rowCount > 0) {
            res.json({ message: 'Task deleted successfully' });
        } else {
            res.status(404).json({ message: 'Task not found' });
        }
    } catch (error) {
        res.status(500).json({ message: 'Failed to delete task', error: error.message });
    }
}]);

  

app.get('/protected',  (req, res) => {
    res.json({
        status: 'success',
        message: 'This is a protected route',
    });
});




app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
