package generator

import (
	"fmt"
	"math/rand"
	"time"
)

var companyNames = []string{
	"Apex Manufacturing Group",
	"Summit Precision Components",
	"Vanguard Valve & Fitting",
	"Lumina Optoelectronics",
	"Nova Tech Materials",
	"Elite Machinery Parts",
	"SinoTech Industrial Solutions",
	"Zenith Industrial Supplies",
}

var slogans = []string{
	"High-Quality Industrial Components for Global Markets.",
	"Precision Engineering and Custom Manufacturing Solutions.",
	"Leading Manufacturer of Industrial Valves and Instrumentation.",
	"Global Exporter of Advanced LED Lighting & Optical Solutions.",
	"ISO 9001 Certified Custom Metal & Plastic Parts Fabrication.",
}

var accentColors = []string{
	"#2563eb", // Royal Blue
	"#059669", // Emerald Green
	"#0d9488", // Teal
	"#4f46e5", // Indigo
	"#db2777", // Pink
}

// GenerateMasqueradeHTML 生成一个独一无二的高端多板块外贸企业官网
func GenerateMasqueradeHTML() string {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	company := companyNames[r.Intn(len(companyNames))]
	slogan := slogans[r.Intn(len(slogans))]
	accent := accentColors[r.Intn(len(accentColors))]

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>%s | Custom Manufacturing & Global Trade</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: %s;
            --primary-hover: %scc;
            --bg: #f8fafc;
            --text-main: #0f172a;
            --text-muted: #475569;
            --card-bg: #ffffff;
            --border: #e2e8f0;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; scroll-behavior: smooth; }
        body {
            font-family: 'Outfit', sans-serif;
            background-color: var(--bg);
            color: var(--text-main);
            line-height: 1.6;
        }
        /* Navigation */
        header {
            background-color: rgba(255, 255, 255, 0.9);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid var(--border);
            position: fixed;
            top: 0; left: 0; width: 100%%;
            z-index: 1000;
        }
        .nav-container {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.25rem 2rem;
        }
        .logo {
            font-weight: 700;
            font-size: 1.4rem;
            color: var(--primary);
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }
        .nav-links {
            display: flex;
            gap: 2rem;
            list-style: none;
        }
        .nav-links a {
            text-decoration: none;
            color: var(--text-muted);
            font-weight: 500;
            transition: color 0.3s;
        }
        .nav-links a:hover {
            color: var(--primary);
        }
        /* Hero Section */
        .hero {
            padding: 10rem 2rem 6rem;
            max-width: 1200px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: 1.2fr 0.8fr;
            align-items: center;
            gap: 4rem;
        }
        .hero-text h1 {
            font-size: 3.5rem;
            font-weight: 700;
            line-height: 1.2;
            margin-bottom: 1.5rem;
            color: var(--text-main);
        }
        .hero-text p {
            font-size: 1.2rem;
            color: var(--text-muted);
            margin-bottom: 2.5rem;
        }
        .cta-buttons {
            display: flex;
            gap: 1rem;
        }
        .btn {
            display: inline-block;
            padding: 0.75rem 2rem;
            border-radius: 0.5rem;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s;
        }
        .btn-primary {
            background-color: var(--primary);
            color: white;
        }
        .btn-primary:hover {
            background-color: var(--primary-hover);
            transform: translateY(-2px);
        }
        .btn-secondary {
            border: 2px solid var(--border);
            color: var(--text-main);
        }
        .btn-secondary:hover {
            background-color: #f1f5f9;
            transform: translateY(-2px);
        }
        .hero-img svg {
            width: 100%%;
            height: auto;
            max-width: 450px;
        }
        /* Advantages Section */
        .section-title {
            text-align: center;
            font-size: 2.2rem;
            font-weight: 700;
            margin-bottom: 3rem;
            position: relative;
        }
        .section-title::after {
            content: '';
            display: block;
            width: 50px;
            height: 4px;
            background-color: var(--primary);
            margin: 0.75rem auto 0;
            border-radius: 2px;
        }
        .advantages {
            background-color: #ffffff;
            padding: 5rem 2rem;
            border-top: 1px solid var(--border);
            border-bottom: 1px solid var(--border);
        }
        .grid-container {
            max-width: 1200px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 2rem;
        }
        .card {
            background-color: var(--bg);
            border: 1px solid var(--border);
            padding: 2.5rem 2rem;
            border-radius: 1rem;
            transition: all 0.3s;
        }
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.05);
            border-color: var(--primary);
        }
        .card-icon {
            color: var(--primary);
            margin-bottom: 1.5rem;
        }
        .card h3 {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 0.75rem;
        }
        .card p {
            color: var(--text-muted);
            font-size: 0.95rem;
        }
        /* Products Section */
        .products {
            padding: 6rem 2rem;
            max-width: 1200px;
            margin: 0 auto;
        }
        .product-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 2rem;
        }
        .product-card {
            background-color: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 1rem;
            overflow: hidden;
            transition: all 0.3s;
        }
        .product-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.05);
        }
        .product-media {
            height: 200px;
            background-color: #f1f5f9;
            display: flex;
            justify-content: center;
            align-items: center;
            color: var(--primary);
        }
        .product-info {
            padding: 1.5rem;
        }
        .product-info h4 {
            font-size: 1.15rem;
            margin-bottom: 0.5rem;
        }
        .product-info p {
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-bottom: 1.5rem;
        }
        .product-info .btn-inquire {
            display: block;
            text-align: center;
            padding: 0.5rem 1rem;
            background-color: var(--bg);
            border: 1px solid var(--border);
            color: var(--text-main);
            border-radius: 0.5rem;
            text-decoration: none;
            font-weight: 500;
            font-size: 0.9rem;
            transition: all 0.3s;
        }
        .product-info .btn-inquire:hover {
            background-color: var(--primary);
            color: white;
            border-color: var(--primary);
        }
        /* About Us Section */
        .about {
            background-color: #ffffff;
            padding: 6rem 2rem;
            border-top: 1px solid var(--border);
            border-bottom: 1px solid var(--border);
        }
        .about-content {
            max-width: 1200px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 4rem;
            align-items: center;
        }
        .about-text h2 {
            font-size: 2.2rem;
            margin-bottom: 1.5rem;
        }
        .about-text p {
            color: var(--text-muted);
            margin-bottom: 1.5rem;
        }
        .cert-badges {
            display: flex;
            gap: 1.5rem;
            margin-top: 2rem;
        }
        .cert-badge {
            border: 1px solid var(--border);
            padding: 0.5rem 1rem;
            border-radius: 0.5rem;
            font-weight: 600;
            font-size: 0.85rem;
            color: var(--text-muted);
            background-color: var(--bg);
        }
        /* Contact Section */
        .contact {
            padding: 6rem 2rem;
            max-width: 1200px;
            margin: 0 auto;
        }
        .contact-grid {
            display: grid;
            grid-template-columns: 0.8fr 1.2fr;
            gap: 4rem;
        }
        .contact-info h3 {
            font-size: 1.8rem;
            margin-bottom: 1.5rem;
        }
        .contact-info p {
            color: var(--text-muted);
            margin-bottom: 2rem;
        }
        .contact-details {
            list-style: none;
        }
        .contact-details li {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1.25rem;
            color: var(--text-muted);
        }
        .contact-details li svg {
            color: var(--primary);
        }
        .contact-form {
            background-color: var(--card-bg);
            border: 1px solid var(--border);
            padding: 3rem;
            border-radius: 1.5rem;
            box-shadow: 0 10px 30px rgba(0,0,0,0.02);
        }
        .form-group {
            margin-bottom: 1.5rem;
        }
        .form-group label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            font-size: 0.95rem;
        }
        .form-control {
            width: 100%%;
            padding: 0.75rem 1rem;
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            background-color: var(--bg);
            font-family: inherit;
            font-size: 1rem;
            transition: all 0.3s;
        }
        .form-control:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15);
        }
        textarea.form-control {
            resize: vertical;
            min-height: 120px;
        }
        .form-status {
            margin-top: 1rem;
            padding: 0.75rem;
            border-radius: 0.5rem;
            font-size: 0.9rem;
            display: none;
        }
        .form-status.success {
            background-color: #d1fae5;
            color: #065f46;
            display: block;
        }
        /* Footer */
        footer {
            background-color: #0f172a;
            color: #94a3b8;
            padding: 4rem 2rem;
            border-top: 1px solid #1e293b;
        }
        .footer-content {
            max-width: 1200px;
            margin: 0 auto;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.95rem;
        }
        .footer-logo {
            font-weight: 700;
            color: #ffffff;
            text-decoration: none;
        }
        @media (max-width: 900px) {
            .hero, .about-content, .contact-grid {
                grid-template-columns: 1fr;
                gap: 3rem;
            }
            .hero-img { order: -1; text-align: center; }
            .nav-links { display: none; }
        }
    </style>
</head>
<body>
    <!-- Header -->
    <header>
        <div class="nav-container">
            <a href="#" class="logo">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
                %s
            </a>
            <ul class="nav-links">
                <li><a href="#">Home</a></li>
                <li><a href="#products">Products</a></li>
                <li><a href="#about">About</a></li>
                <li><a href="#contact">Contact</a></li>
            </ul>
        </div>
    </header>

    <!-- Hero Section -->
    <section class="hero">
        <div class="hero-text">
            <h1>%s</h1>
            <p>%s We deliver high-precision engineering, OEM production, and supply chain reliability to over 40 countries.</p>
            <div class="cta-buttons">
                <a href="#contact" class="btn btn-primary">Get a Quote</a>
                <a href="#products" class="btn btn-secondary">View Products</a>
            </div>
        </div>
        <div class="hero-img">
            <svg viewBox="0 0 500 500" fill="none" xmlns="http://www.w3.org/2000/svg">
                <circle cx="250" cy="250" r="180" fill="%s" fill-opacity="0.08"/>
                <rect x="180" y="150" width="140" height="200" rx="10" fill="#ffffff" stroke="var(--primary)" stroke-width="6"/>
                <circle cx="250" cy="220" r="30" fill="var(--primary)" fill-opacity="0.2" stroke="var(--primary)" stroke-width="4"/>
                <path d="M150 380h200v30H150z" fill="#94a3b8"/>
                <path d="M220 280h60v40h-60z" fill="var(--primary)"/>
            </svg>
        </div>
    </section>

    <!-- Advantages Section -->
    <section class="advantages">
        <h2 class="section-title">Our Strengths</h2>
        <div class="grid-container">
            <div class="card">
                <svg class="card-icon" width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-dasharray="none" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4l3 3"/></svg>
                <h3>On-Time Delivery</h3>
                <p>Global logistics support ensuring your cargo reaches your port safely and precisely on schedule.</p>
            </div>
            <div class="card">
                <svg class="card-icon" width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                <h3>Quality Assurance</h3>
                <p>Strict QC team checking all products from raw materials to final packaging. Zero tolerance for defects.</p>
            </div>
            <div class="card">
                <svg class="card-icon" width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg>
                <h3>OEM/ODM Service</h3>
                <p>Equipped with modern CNC tooling and mold workshops. Custom blueprints and specs are fully welcome.</p>
            </div>
        </div>
    </section>

    <!-- Products Section -->
    <section class="products" id="products">
        <h2 class="section-title">Product Categories</h2>
        <div class="product-grid">
            <div class="product-card">
                <div class="product-media">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>
                </div>
                <div class="product-info">
                    <h4>Precision Hardware</h4>
                    <p>High-tolerance CNC parts, custom fittings, and custom machined fasteners for industrial machines.</p>
                    <a href="#contact" class="btn-inquire">Request Details</a>
                </div>
            </div>
            <div class="product-card">
                <div class="product-media">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
                </div>
                <div class="product-info">
                    <h4>Electric Components</h4>
                    <p>Robust relay modules, electrical switchgear components, and custom distribution terminal blocks.</p>
                    <a href="#contact" class="btn-inquire">Request Details</a>
                </div>
            </div>
            <div class="product-card">
                <div class="product-media">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M8 12h8"/></svg>
                </div>
                <div class="product-info">
                    <h4>Flow Control Valves</h4>
                    <p>Heavy duty stainless steel ball valves, butterfly valves, and pneumatic control assemblies.</p>
                    <a href="#contact" class="btn-inquire">Request Details</a>
                </div>
            </div>
            <div class="product-card">
                <div class="product-media">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>
                </div>
                <div class="product-info">
                    <h4>Lighting Equipment</h4>
                    <p>Energy-saving LED floodlights, explosion-proof industrial lighting, and optical lenses.</p>
                    <a href="#contact" class="btn-inquire">Request Details</a>
                </div>
            </div>
        </div>
    </section>

    <!-- About Us Section -->
    <section class="about" id="about">
        <div class="about-content">
            <div class="about-img">
                <svg viewBox="0 0 500 400" fill="none" xmlns="http://www.w3.org/2000/svg">
                    <rect width="500" height="400" rx="20" fill="#f1f5f9"/>
                    <path d="M50 300l100-80 120 70 180-140" stroke="var(--primary)" stroke-width="4" stroke-linecap="round"/>
                    <circle cx="150" cy="220" r="6" fill="var(--primary)"/>
                    <circle cx="270" cy="290" r="6" fill="var(--primary)"/>
                    <circle cx="450" cy="150" r="6" fill="var(--primary)"/>
                    <text x="50" y="80" fill="var(--text-muted)" font-weight="600" font-size="16">Global Shipment Vol. (YTD)</text>
                </svg>
            </div>
            <div class="about-text">
                <h2>About Us</h2>
                <p>For more than a decade, %s has been a reliable manufacturer in engineering fabrication and global trading. Our manufacturing plants are equipped with high-precision tooling and robotic lines.</p>
                <p>We work tightly with global partners to bring ISO-compliant parts to hardware, energy, and electronics industries. Custom packaging, barcode labeling, and DDP shipments are part of our turnkey solutions.</p>
                <div class="cert-badges">
                    <div class="cert-badge">ISO 9001</div>
                    <div class="cert-badge">CE Certified</div>
                    <div class="cert-badge">RoHS Compliant</div>
                </div>
            </div>
        </div>
    </section>

    <!-- Contact Section -->
    <section class="contact" id="contact">
        <div class="contact-grid">
            <div class="contact-info">
                <h3>Contact Us</h3>
                <p>Have custom requirements or need a quick price quotation? Send us your technical drawings or product specs, and our sales team will reach out to you within 24 hours.</p>
                <ul class="contact-details">
                    <li>
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
                        export@%s.com
                    </li>
                    <li>
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.79 19.79 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6 19.79 19.79 0 0 1-3.07-8.67A2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72 12.84 12.84 0 0 0 .7 2.81 2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45 12.84 12.84 0 0 0 2.81.7A2 2 0 0 1 22 16.92z"/></svg>
                        +86 755 8899 7788
                    </li>
                    <li>
                        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>
                        Industrial Zone High-Tech Park, Nanshan, Shenzhen, China
                    </li>
                </ul>
            </div>
            <div class="contact-form">
                <form id="inquiryForm" onsubmit="handleSubmit(event)">
                    <div class="form-group">
                        <label for="name">Your Name</label>
                        <input type="text" id="name" class="form-control" required placeholder="John Doe">
                    </div>
                    <div class="form-group">
                        <label for="email">Business Email</label>
                        <input type="email" id="email" class="form-control" required placeholder="john@company.com">
                    </div>
                    <div class="form-group">
                        <label for="message">Detailed Requirements</label>
                        <textarea id="message" class="form-control" required placeholder="Please describe the specifications, quantities, and target shipping address..."></textarea>
                    </div>
                    <button type="submit" class="btn btn-primary" style="width: 100%%; border: none; cursor: pointer;">Send Inquiry</button>
                    <div id="statusMessage" class="form-status"></div>
                </form>
            </div>
        </div>
    </section>

    <!-- Footer -->
    <footer>
        <div class="footer-content">
            <a href="#" class="footer-logo">%s</a>
            <div>&copy; 2026 %s Group. All rights reserved.</div>
        </div>
    </footer>

    <script>
        function handleSubmit(e) {
            e.preventDefault();
            const name = document.getElementById('name').value;
            const status = document.getElementById('statusMessage');
            
            // 仿真提交反馈
            status.textContent = "Thank you, " + name + "! Your message has been sent successfully. We will contact you soon.";
            status.className = "form-status success";
            
            document.getElementById('inquiryForm').reset();
        }
    </script>
</body>
</html>
`, company, accent, accent, company, company, slogan, accent, company, company, company, company)
}

