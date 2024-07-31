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
const PORT = 3000||null;

const pool = new Pool({
    user: 'postgres.fqvfkmnkexkmhswnlxjg',
    host: 'aws-0-ap-southeast-1.pooler.supabase.com',
    database: 'postgres',
    password: 'Kaviswar@123',
    port: 6543
});

app.use(cors());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());

const secretKey = process.env.SECRET_KEY || "97b34701a945e7d7717fbf4d678f280766a6a64dc7662d7f68318f13d0fe01c085ab970eb17daa8138457f3dac983cd92a6f8e770462ef5ccbfd4d39d9a61bc4";

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

app.post('/api/decodeToken', validateToken, async (req, res) => {
    console.log('api decode requested');
    try {
        const { token } = req.body;
        console.log(token);

        const decodedToken = jwt.verify(token, secretKey);
        const { username } = decodedToken;

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
        console.error('Error decoding token:', error.message);
        res.status(400).json({ error: 'Failed to decode token' });
    }
});

app.post('/api/register', async (req, res) => {
    const { username, email, password, full_name, dob } = req.body;

    try {
        const checkQuery = 'SELECT * FROM users WHERE username = $1';
        const checkResult = await pool.query(checkQuery, [username]);

        if (checkResult.rows.length > 0) {
            return res.status(400).json({
                status: 'error',
                message: 'Username already taken',
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const query = 'INSERT INTO users (username, password, email, full_name, dob) VALUES ($1, $2, $3, $4, $5) RETURNING *';
        const values = [username, hashedPassword, email, full_name, dob];
        await pool.query(query, values);

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
        const query = 'SELECT * FROM users WHERE username = $1';
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

        res.json({
            isvalid: true,
            token,
            profileExists: 1
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({
            status: 'error',
            message: 'Internal Server Error',
        });
    }
});

app.post('/api/userProfile', validateToken, async (req, res) => {
    const { username } = req.body;
    try {
        const userResult = await pool.query('SELECT * FROM Users WHERE username = $1', [username]);
        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        const user = userResult.rows[0];

        const tasksResult = await pool.query(`
            SELECT 
                COUNT(*) FILTER (WHERE status = 'pending') AS pending,
                COUNT(*) FILTER (WHERE status = 'In Progress') AS in_progress,
                COUNT(*) FILTER (WHERE status = 'Completed') AS completed
            FROM Tasks
            WHERE assignedto = $1`, [username]);

        const projectsResult = await pool.query(`
            SELECT COUNT(DISTINCT project_id) AS projects_count
            FROM Projects
            WHERE members @> $1::jsonb OR project_leader = $2`, [JSON.stringify([username]), username]);

        res.json({
            full_name: user.full_name,
            email: user.email,
            dob: user.dob,
            tasks: tasksResult.rows[0],
            projects_count: projectsResult.rows[0].projects_count,
        });
    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/api/updateUserProfile', validateToken, async (req, res) => {
    const { username } = req.user;
    const { full_name, email, dob } = req.body;

    try {
        await pool.query(
            'UPDATE Users SET full_name = $1, email = $2, dob = $3 WHERE username = $4',
            [full_name, email, dob, username]
        );
        res.sendStatus(200);
    } catch (error) {
        console.error('Error updating user profile:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/api/users', validateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT username, full_name FROM Users');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/projects', validateToken, async (req, res) => {
    const { project_name, project_leader, members } = req.body;
    try {
        const result = await pool.query(
            'INSERT INTO Projects (project_name, project_leader) VALUES ($1, $2) RETURNING project_id',
            [project_name, project_leader]
        );
        const project_id = result.rows[0].project_id;

        const requestPromises = members.map(member =>
            pool.query(
                'INSERT INTO Requests (username, project_id, status) VALUES ($1, $2, $3)',
                [member, project_id, 'Pending']
            )
        );

        await Promise.all(requestPromises);

        res.status(201).json({ message: 'Project created and requests sent successfully' });
    } catch (error) {
        console.error('Error creating project and sending requests:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/requests', validateToken, async (req, res) => {
    try {
        const username = req.user.username;
        const requests = await pool.query('SELECT * FROM Requests WHERE username = $1 AND status = $2', [username, 'Pending']);
        res.json(requests.rows);
    } catch (err) {
        console.error('Error fetching requests:', err.message);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/requests/accept', validateToken, async (req, res) => {
    const { request_id } = req.body;

    try {
        const requestResult = await pool.query('SELECT * FROM Requests WHERE request_id = $1', [request_id]);
        if (requestResult.rows.length === 0) {
            return res.status(404).json({ message: 'Request not found' });
        }

        const request = requestResult.rows[0];
        const { project_id, username } = request;

        // Update the request status
        await pool.query('UPDATE Requests SET status = $1 WHERE request_id = $2', ['Accepted', request_id]);

        // Remove the request from the Requests table
        await pool.query('DELETE FROM Requests WHERE request_id = $1', [request_id]);

        // Add the user to the project's members
        const projectResult = await pool.query('SELECT members FROM Projects WHERE project_id = $1', [project_id]);
        const project = projectResult.rows[0];
        const members = project.members || [];
        members.push(username);

        await pool.query('UPDATE Projects SET members = $1 WHERE project_id = $2', [JSON.stringify(members), project_id]);

        res.status(200).json({ message: 'Request accepted and user added to project members' });
    } catch (err) {
        console.error('Error accepting request:', err.message);
        res.status(500).json({ message: 'Server error' });
    }
});


app.post('/api/requests/reject', validateToken, async (req, res) => {
    const { request_id } = req.body;

    try {
        const requestResult = await pool.query('SELECT * FROM Requests WHERE request_id = $1', [request_id]);
        if (requestResult.rows.length === 0) {
            return res.status(404).json({ message: 'Request not found' });
        }

        // Update the request status
        await pool.query('UPDATE Requests SET status = $1 WHERE request_id = $2', ['Rejected', request_id]);

        // Optionally, you can also remove the request from the Requests table if you don't need to keep rejected requests
        await pool.query('DELETE FROM Requests WHERE request_id = $1', [request_id]);

        res.status(200).json({ message: 'Request rejected' });
    } catch (err) {
        console.error('Error rejecting request:', err.message);
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/userProjects', validateToken, async (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).json({ error: 'Username is required' });
    }

    try {
        const query = 'SELECT * FROM projects WHERE project_leader = $1 OR members::jsonb @> $2::jsonb';
        const values = [username, JSON.stringify([username])];
        const result = await pool.query(query, values);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'No projects found for the user' });
        }

        res.status(200).json(result.rows);
    } catch (error) {
        console.error('Error fetching user projects:', error.message);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

app.post('/api/projectMembers', validateToken, async (req, res) => {
    const { project_id } = req.body;

    if (!project_id) {
        return res.status(400).json({ error: 'Project ID is required' });
    }

    try {
        const query = 'SELECT members FROM Projects WHERE project_id = $1';
        const result = await pool.query(query, [project_id]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'No members found for this project' });
        }

        const members = result.rows[0].members;
        res.status(200).json({ members });
    } catch (error) {
        console.error('Error fetching project members:', error.message);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});



app.post('/api/createTask', validateToken, async (req, res) => {
    const { project_id, task_name, assigned_to, status, due_date, category, priority } = req.body;
    const assigner = req.user.username;

    try {
        const query = `
            INSERT INTO Tasks (assigner, assignedto, project_id, task_name, status, due_date, category, priority)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING task_id
        `;
        const values = [assigner, assigned_to, project_id, task_name, status, due_date, category, priority];
        const result = await pool.query(query, values);
        res.status(201).json({ task_id: result.rows[0].task_id, message: 'Task created successfully' });
    } catch (err) {
        console.error('Error creating task:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/api/getTasks', validateToken, async (req, res) => {
    const { username, filters } = req.body;

    // Base query
    let query = `
        SELECT t.task_id, t.task_name, t.status, t.priority, p.project_name
        FROM Tasks t
        JOIN Projects p ON t.project_id = p.project_id
        WHERE t.assignedto = $1
    `;
    
    // Array to hold parameters for the query
    const params = [username];
    
    // Building query and parameters based on filters
    let filterIndex = 2; // Start index for filter parameters

    if (filters.project_id) {
        query += ` AND t.project_id = $${filterIndex++}`;
        params.push(filters.project_id);
    }
    if (filters.status) {
        query += ` AND t.status = $${filterIndex++}`;
        params.push(filters.status);
    }
    if (filters.priority) {
        query += ` AND t.priority = $${filterIndex++}`;
        params.push(filters.priority);
    }

    try {
        const { rows } = await pool.query(query, params);
        res.json(rows);
    } catch (err) {
        console.error('Error fetching tasks:', err);
        res.sendStatus(500);
    }
});

app.get('/api/getProjects', validateToken, async (req, res) => {
    try {
        const { rows } = await pool.query('SELECT project_id, project_name FROM Projects');
        res.json(rows);
    } catch (err) {
        console.error('Error fetching projects:', err);
        res.sendStatus(500);
    }
});

app.post('/api/updateTask', validateToken, async (req, res) => {
    const { task_id, task_name, status, priority, project_id } = req.body;

    try {
        await pool.query(`
            UPDATE Tasks
            SET task_name = $1, status = $2, priority = $3, project_id = $4
            WHERE task_id = $5
        `, [task_name, status, priority, project_id, task_id]);
        res.sendStatus(200);
    } catch (err) {
        console.error('Error updating task:', err);
        res.sendStatus(500);
    }
});

app.post('/api/deleteTask', validateToken, async (req, res) => {
    const { task_id } = req.body;

    try {
        await pool.query('DELETE FROM Tasks WHERE task_id = $1', [task_id]);
        res.sendStatus(200);
    } catch (err) {
        console.error('Error deleting task:', err);
        res.sendStatus(500);
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
