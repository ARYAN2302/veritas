from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
import time

class PDFReporter:
    def __init__(self, filename="Veritas_Security_Report.pdf"):
        self.filename = filename

    def generate_report(self, target_name, results):
        c = canvas.Canvas(self.filename, pagesize=letter)
        width, height = letter
        
        # Header
        c.setFont("Helvetica-Bold", 24)
        c.drawString(50, height - 50, "VERITAS Security Assessment")
        
        c.setFont("Helvetica", 12)
        c.drawString(50, height - 80, f"Target System: {target_name}")
        c.drawString(50, height - 100, f"Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Handle both dict and VulnerabilityEntry objects
        def get_success(r):
            return r.success if hasattr(r, 'success') else r.get('success', False)
        def get_name(r):
            return r.attack_name if hasattr(r, 'attack_name') else r.get('name', 'Unknown')
        def get_prompt(r):
            return r.prompt if hasattr(r, 'prompt') else r.get('prompt', '')
        def get_response(r):
            return r.response if hasattr(r, 'response') else r.get('response', '')
        
        # Summary Score
        vuln_count = sum(1 for r in results if get_success(r))
        total = len(results)
        score = 100 - int((vuln_count/total) * 100) if total > 0 else 100
        
        c.setFillColor(colors.red if score < 50 else colors.green)
        c.setFont("Helvetica-Bold", 16)
        c.drawString(400, height - 80, f"Safety Score: {score}/100")
        c.setFillColor(colors.black)
        
        # Findings Table
        y = height - 150
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "Detailed Findings:")
        y -= 30
        
        c.setFont("Helvetica", 10)
        for res in results:
            success = get_success(res)
            status = "CRITICAL" if success else "SAFE"
            color = colors.red if success else colors.green
            
            c.setFillColor(color)
            c.drawString(50, y, f"[{status}] {get_name(res)}")
            c.setFillColor(colors.black)
            
            prompt = get_prompt(res)
            c.drawString(200, y, f"Prompt: {prompt[:40]}...")
            y -= 20
            
            if success:
                c.setFont("Courier", 8)
                response = get_response(res)
                c.drawString(70, y, f"Response Payload: {response[:60]}...")
                y -= 15
                c.setFont("Helvetica", 10)
            
            y -= 10
            if y < 50: # New page
                c.showPage()
                y = height - 50
                
        c.save()
        return self.filename