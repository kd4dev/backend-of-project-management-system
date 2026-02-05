const API_URL = 'http://localhost:8000/api/v1';
const TEST_TIMESTAMP = Date.now();
const USER_A = {
    email: `test_${TEST_TIMESTAMP}@example.com`,
    username: `user_${TEST_TIMESTAMP}`,
    password: 'Password123!'
};

const ADMIN_USER = {
    email: 'admin@example.com',
    password: 'Admin123!',
};

let accessToken = '';
let projectId = '';
let taskId = '';

async function request(endpoint, method = 'GET', body = null) {
    const headers = { 'Content-Type': 'application/json' };
    if (accessToken) headers['Authorization'] = `Bearer ${accessToken}`;

    const options = { method, headers };
    if (body) options.body = JSON.stringify(body);

    const res = await fetch(`${API_URL}${endpoint}`, options);
    const data = await res.json();
    
    if (!res.ok) {
        throw new Error(data.message || `HTTP ${res.status}`);
    }
    return data;
}

async function runTests() {
    console.log('🚀 Starting Backend Tests (Fetch Version)...\n');

    try {
        // --- AUTH TESTS ---
        console.log('1. Testing Authentication...');
        
        // Register
        try {
            await request('/auth/register', 'POST', USER_A);
            console.log('  ✅ Register Success');
        } catch (e) {
            console.error('  ❌ Register Failed:', e.message);
            process.exit(1);
        }

        // Login (admin)
        try {
            const data = await request('/auth/login', 'POST', {
                email: ADMIN_USER.email,
                password: ADMIN_USER.password
            });
            accessToken = data.data.accessToken;
            console.log('  ✅ Admin Login Success');
        } catch (e) {
            console.error('  ❌ Admin Login Failed:', e.message);
            process.exit(1);
        }

        // --- PROJECT TESTS ---
        console.log('\n2. Testing Projects...');

        // Create Project
        try {
            const data = await request('/projects', 'POST', {
                name: `Project ${TEST_TIMESTAMP}`,
                description: 'Test Description'
            });
            projectId = data.data._id;
            console.log('  ✅ Create Project Success');
        } catch (e) {
            console.error('  ❌ Create Project Failed:', e.message);
        }

        // --- TASK TESTS ---
        console.log('\n3. Testing Tasks...');

        // Create Task
        try {
            const data = await request(`/tasks/${projectId}`, 'POST', {
                title: 'Test Task',
                description: 'Task Description',
                priority: 'high',
                status: 'todo',
                dueDate: new Date().toISOString()
            });
            taskId = data.data._id;
            console.log('  ✅ Create Task Success');
        } catch (e) {
            console.error('  ❌ Create Task Failed:', e.message);
        }

        // --- NOTE TESTS ---
        console.log('\n4. Testing Notes...');

        // Create Note
        try {
            await request(`/notes/${projectId}`, 'POST', {
                content: 'This is a test note'
            });
            console.log('  ✅ Create Note Success');
        } catch (e) {
            console.error('  ❌ Create Note Failed:', e.message);
        }

        console.log('\n🎉 All Backend Tests Completed!');

    } catch (error) {
        console.error('Unexpected Error:', error);
    }
}

runTests();
