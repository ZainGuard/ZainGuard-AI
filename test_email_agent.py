#!/usr/bin/env python3
"""
Test script for the Email Investigation Agent.
This demonstrates how to create and use the custom email investigation agent.
"""

import asyncio
import json
from src.core.agent_manager import agent_manager
from src.agents.email_investigation_agent import EmailInvestigationAgent


async def test_email_investigation():
    """Test the email investigation agent with sample data."""
    
    print("🔍 Testing Email Investigation Agent")
    print("=" * 50)
    
    # Register the email investigation agent type
    agent_manager.register_agent_type("email_investigation", EmailInvestigationAgent)
    
    # Create an email investigation agent
    agent = agent_manager.create_agent(
        agent_type="email_investigation",
        agent_id="email-agent-001",
        name="My Email Investigation Agent",
        description="Custom agent for email security analysis"
    )
    
    # Start the agent
    await agent.start()
    print(f"✅ Agent created and started: {agent.name}")
    
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
    
    print("\n📧 Sample Email Data:")
    print(f"Subject: {sample_email['subject']}")
    print(f"From: {sample_email['from']}")
    print(f"Content length: {len(sample_email['content'])} characters")
    print(f"Attachments: {len(sample_email['attachments'])}")
    
    # Submit investigation task
    print("\n🚀 Submitting email investigation task...")
    task_id = await agent.submit_task(
        task_type="email_investigation",
        input_data=sample_email,
        priority=1
    )
    
    print(f"📋 Task submitted with ID: {task_id}")
    
    # Wait for processing
    print("\n⏳ Waiting for investigation to complete...")
    await asyncio.sleep(5)  # Wait for processing
    
    # Check task status
    status = agent.get_task_status(task_id)
    if status is None:
        print(f"\n❌ Task not found: {task_id}")
        return
    
    print(f"\n📊 Task Status: {status['status']}")
    
    if status['status'] == 'completed':
        results = status['result']['investigation_results']
        
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
        
        # Display key findings
        print("\n🔍 Key Findings:")
        
        # Header analysis
        header_analysis = results.get('header_analysis', {})
        if header_analysis.get('spoofing_indicators'):
            print("   • Email spoofing indicators detected")
        if header_analysis.get('security_flags'):
            print("   • Security flags in headers")
        
        # Content analysis
        content_analysis = results.get('content_analysis', {})
        if content_analysis.get('phishing_indicators'):
            print(f"   • Phishing indicators found: {len(content_analysis['phishing_indicators'])}")
        
        # URL analysis
        url_analysis = results.get('url_analysis', {})
        if url_analysis.get('suspicious_urls'):
            print(f"   • Suspicious URLs detected: {len(url_analysis['suspicious_urls'])}")
        
        # Attachment analysis
        attachment_analysis = results.get('attachment_analysis', {})
        if attachment_analysis.get('suspicious_attachments'):
            print(f"   • Suspicious attachments: {len(attachment_analysis['suspicious_attachments'])}")
        
        print(f"\n✅ Investigation completed successfully!")
        print(f"📄 Full results saved with investigation ID: {task_id}")
        
    elif status['status'] == 'failed':
        print(f"❌ Investigation failed: {status.get('error', 'Unknown error')}")
    
    # Stop the agent
    await agent.stop()
    print(f"\n🛑 Agent stopped: {agent.name}")


if __name__ == "__main__":
    print("🚀 Starting Email Investigation Agent Test")
    asyncio.run(test_email_investigation())
