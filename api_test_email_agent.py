#!/usr/bin/env python3
"""
API test script for the Email Investigation Agent.
This demonstrates how to use the email investigation agent via the REST API.
"""

import requests
import json
import time


def test_email_agent_api():
    """Test the email investigation agent via API."""
    
    base_url = "http://localhost:8000/api/v1"
    
    print("🔍 Testing Email Investigation Agent via API")
    print("=" * 50)
    
    # Sample suspicious email data
    sample_email = {
        "subject": "URGENT: Verify Your Account - Action Required Immediately",
        "from": "security@bank-security-alert.com",
        "to": "user@company.com",
        "headers": {
            "from": "security@bank-security-alert.com",
            "reply-to": "noreply@different-domain.com",
            "message-id": "<12345@fake-bank.com>",
            "received": "from fake-proxy.com by relay.example.com",
            "authentication-results": "none"
        },
        "content": """
        <html>
        <body>
        <h1>URGENT SECURITY ALERT</h1>
        <p>Dear Customer,</p>
        <p>We have detected suspicious activity on your account. Please verify your identity immediately to prevent account suspension.</p>
        <p>Click here to verify: <a href="http://fake-bank-login.tk/verify">VERIFY NOW</a></p>
        <p>This link will expire in 24 hours. Act now to secure your account!</p>
        <p>If you don't act immediately, your account will be suspended.</p>
        </body>
        </html>
        """,
        "attachments": [
            {
                "filename": "account_verification.exe",
                "size": 5242880,
                "hash": "abc123def456"
            }
        ]
    }
    
    try:
        # 1. Create an email investigation agent
        print("🤖 Creating email investigation agent...")
        agent_data = {
            "agent_type": "email_investigation",
            "agent_id": "api-email-agent-001",
            "name": "API Email Investigation Agent",
            "description": "Email investigation agent created via API"
        }
        
        response = requests.post(f"{base_url}/agents", json=agent_data)
        if response.status_code == 201 or response.status_code == 200:
            agent_info = response.json()
            print(f"✅ Agent ready: {agent_info['name']}")
            agent_id = agent_info['agent_id']
        else:
            print(f"❌ Failed to create agent: {response.status_code} - {response.text}")
            return
        
        # 2. Submit email investigation task
        print("\n📧 Submitting email investigation task...")
        task_data = {
            "task_type": "email_investigation",
            "input_data": sample_email,
            "priority": 1
        }
        
        response = requests.post(f"{base_url}/tasks/{agent_id}/submit", json=task_data)
        if response.status_code == 201 or response.status_code == 200:
            task_info = response.json()
            task_id = task_info['task_id']
            print(f"✅ Task submitted: {task_id}")
        else:
            print(f"❌ Failed to submit task: {response.status_code} - {response.text}")
            return
        
        # 3. Wait for processing and check status
        print("\n⏳ Waiting for investigation to complete...")
        max_attempts = 30
        attempt = 0
        
        while attempt < max_attempts:
            time.sleep(2)
            attempt += 1
            
            response = requests.get(f"{base_url}/tasks/{agent_id}/{task_id}")
            if response.status_code == 200:
                task_status = response.json()
                status = task_status['status']
                
                print(f"📊 Task status: {status} (attempt {attempt}/{max_attempts})")
                
                if status == 'completed':
                    results = task_status['result']['investigation_results']
                    
                    print("\n🔍 INVESTIGATION RESULTS:")
                    print("=" * 50)
                    
                    # Display risk assessment
                    risk_assessment = results.get('risk_assessment', {})
                    print(f"🚨 Risk Level: {risk_assessment.get('risk_level', 'UNKNOWN')}")
                    print(f"📊 Risk Score: {risk_assessment.get('risk_score', 0)}/100")
                    
                    if risk_assessment.get('risk_factors'):
                        print("\n⚠️  Risk Factors:")
                        for factor in risk_assessment['risk_factors']:
                            print(f"   • {factor}")
                    
                    # Display recommendations
                    recommendations = results.get('recommendations', [])
                    if recommendations:
                        print("\n💡 Recommendations:")
                        for rec in recommendations:
                            print(f"   • {rec}")
                    
                    print(f"\n✅ Investigation completed successfully!")
                    break
                    
                elif status == 'failed':
                    print(f"❌ Investigation failed: {task_status.get('error', 'Unknown error')}")
                    break
            else:
                print(f"❌ Failed to get task status: {response.status_code}")
                break
        
        if attempt >= max_attempts:
            print("⏰ Timeout waiting for investigation to complete")
        
        # 4. List all agents to show our agent is registered
        print("\n📋 Listing all agents...")
        response = requests.get(f"{base_url}/agents")
        if response.status_code == 200:
            agents = response.json()
            print(f"📊 Total agents: {len(agents)}")
            for agent in agents:
                if agent['agent_id'] == agent_id:
                    print(f"   • {agent['name']} ({agent['agent_type']}) - Running: {agent['is_running']}")
        
    except requests.exceptions.ConnectionError:
        print("❌ Cannot connect to server. Make sure the server is running on http://localhost:8000")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    print("🚀 Starting Email Investigation Agent API Test")
    test_email_agent_api()
