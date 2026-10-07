/**
 * Count-up animations, scroll-triggered reveals, and particle effects.
 */

// ── Animated Counter ──────────────────────────────────────────────────────────

function animateCounter(element, target, duration = 1500) {
    const start = 0;
    const startTime = performance.now();

    function update(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);

        // Ease out cubic
        const eased = 1 - Math.pow(1 - progress, 3);
        const current = Math.round(start + (target - start) * eased);

        element.textContent = current.toLocaleString();

        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }

    requestAnimationFrame(update);
}

// ── Intersection Observer for Scroll Animations ──────────────────────────────

function initScrollAnimations() {
    const observer = new IntersectionObserver(
        (entries) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting) {
                    entry.target.classList.add('revealed');

                    // Trigger counter animation
                    if (entry.target.dataset.countTarget) {
                        const target = parseInt(entry.target.dataset.countTarget, 10);
                        animateCounter(entry.target, target);
                    }

                    observer.unobserve(entry.target);
                }
            });
        },
        {
            threshold: 0.15,
            rootMargin: '0px 0px -50px 0px',
        }
    );

    document.querySelectorAll('[data-animate]').forEach((el) => {
        observer.observe(el);
    });

    document.querySelectorAll('[data-count-target]').forEach((el) => {
        observer.observe(el);
    });
}

// ── Score Ring Animation ─────────────────────────────────────────────────────

function initScoreRings() {
    const rings = document.querySelectorAll('.score-ring__progress');
    
    const observer = new IntersectionObserver(
        (entries) => {
            entries.forEach((entry) => {
                if (entry.isIntersecting) {
                    const circle = entry.target;
                    const score = parseInt(circle.dataset.score, 10);
                    const radius = parseFloat(circle.getAttribute('r'));
                    const circumference = 2 * Math.PI * radius;

                    circle.style.strokeDasharray = circumference;
                    circle.style.strokeDashoffset = circumference;

                    // Trigger animation on next frame
                    requestAnimationFrame(() => {
                        const offset = circumference - (score / 100) * circumference;
                        circle.style.strokeDashoffset = offset;
                    });

                    // Animate the score value text
                    const container = circle.closest('.score-ring');
                    const valueEl = container?.querySelector('.score-ring__value');
                    if (valueEl) {
                        animateCounter(valueEl, score);
                    }

                    observer.unobserve(entry.target);
                }
            });
        },
        { threshold: 0.3 }
    );

    rings.forEach((ring) => observer.observe(ring));
}

// ── Particle Effect ──────────────────────────────────────────────────────────

function initParticles() {
    const canvas = document.getElementById('particle-canvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    let particles = [];
    let animationId;

    function resize() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }

    function createParticle() {
        return {
            x: Math.random() * canvas.width,
            y: Math.random() * canvas.height,
            radius: Math.random() * 1.5 + 0.5,
            vx: (Math.random() - 0.5) * 0.3,
            vy: (Math.random() - 0.5) * 0.3,
            opacity: Math.random() * 0.3 + 0.1,
        };
    }

    function init() {
        resize();
        particles = [];
        const count = Math.min(Math.floor((canvas.width * canvas.height) / 15000), 80);
        for (let i = 0; i < count; i++) {
            particles.push(createParticle());
        }
    }

    function draw() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        particles.forEach((p) => {
            ctx.beginPath();
            ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
            ctx.fillStyle = `rgba(129, 140, 248, ${p.opacity})`;
            ctx.fill();

            p.x += p.vx;
            p.y += p.vy;

            if (p.x < 0 || p.x > canvas.width) p.vx *= -1;
            if (p.y < 0 || p.y > canvas.height) p.vy *= -1;
        });

        // Draw connections
        for (let i = 0; i < particles.length; i++) {
            for (let j = i + 1; j < particles.length; j++) {
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < 120) {
                    ctx.beginPath();
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.strokeStyle = `rgba(129, 140, 248, ${0.06 * (1 - dist / 120)})`;
                    ctx.lineWidth = 0.5;
                    ctx.stroke();
                }
            }
        }

        animationId = requestAnimationFrame(draw);
    }

    init();
    draw();

    window.addEventListener('resize', () => {
        cancelAnimationFrame(animationId);
        init();
        draw();
    });
}

// ── Initialize All Animations ────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    initScrollAnimations();
    initScoreRings();
    initParticles();
});
