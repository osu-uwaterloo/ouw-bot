class Triangles {
	equalateralRatio = 0.8660254037844386;
	baseVelocity = 50;
	triangleSize = 80;
	spawnRatio = 0.4;
	baseColor = [241, 200, 20];

	constructor(svg, options = {}) {
		this.svg = svg;
		const viewBox = svg.getAttribute('viewBox').split(' ').map(Number);
		this.width = viewBox[2];
		this.height = viewBox[3];
		this.triangleSize = this.height * 0.4;
		this.maxCount = Math.round(this.width * this.height / (this.triangleSize * this.triangleSize) * this.spawnRatio * 7);
		//this.baseVelocity = this.height * 0.1;
		this.init();
		return this;
	}

	init() {
		this.svg.innerHTML = '';
		this.addTriangles(true);
		window.addEventListener('visibilitychange', this.onVisibilityChange.bind(this));
		this.animation = requestAnimationFrame(this.tick.bind(this));
	}

	tick(time) {
		if (!this.lastTime) this.lastTime = time;
		const elapsed = time - this.lastTime;
		this.lastTime = time;
		if (!this.svg) {
			this.destory();
			return;
		}
		this.update(elapsed);
		this.animation = requestAnimationFrame(this.tick.bind(this));
	}

	update(elapsed) {
		const triangles = this.svg.querySelectorAll('polygon');
		const movedDistance = elapsed * 1 * this.baseVelocity / (this.height / this.triangleSize) / 2500;
		for (const triangle of triangles) {
			let y = Number(triangle.getAttribute('y'));
			const scale = Number(triangle.getAttribute('scale'));
			const size = Number(triangle.getAttribute('size'));
			y -= Math.max(0.35, scale) * movedDistance;
			if (y < - size / 2) {
				triangle.remove();
				this.addTriangle();
				continue;
			}
			triangle.setAttribute('y', y);
			this.renderTriangle(triangle);
		}

	}

	addTriangles(randomY = false) {
		const currentCount = this.svg.childElementCount;
		for (let i = 0; i < this.maxCount - currentCount; i++) {
			this.addTriangle(randomY);
		}
	}

	addTriangle(randomY = false) {
		const stdDev = 0.16;
		const mean = 0.5;
		const [u1, u2] = [Math.random(), Math.random()];
		const randStdNormal = Math.sqrt(-2 * Math.log(u1)) * Math.sin(2 * Math.PI * u2);
		const scale = Math.max(1 * (mean + stdDev * randStdNormal), 0.1);
		const size = this.triangleSize * scale;
		const x = this.randomBetween(- size * this.equalateralRatio, this.width + size * this.equalateralRatio);
		const y = randomY ? this.randomBetween(- size / 2, this.height + size) : this.height + size;
		const fill = this.randomShade();
		const polygon = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
		polygon.setAttribute('x', x);
		polygon.setAttribute('y', y);
		polygon.setAttribute('scale', scale);
		polygon.setAttribute('size', size);
		polygon.setAttribute('fill', fill);

		this.renderTriangle(polygon);
		this.svg.appendChild(polygon);
	}

	renderTriangle(polygonDom) {
		if (!polygonDom) return;
		const x = Number(polygonDom.getAttribute('x'));
		const y = Number(polygonDom.getAttribute('y'));
		const size = Number(polygonDom.getAttribute('size'));
		const x1 = x;
		const y1 = y - size;
		const x2 = x - size * this.equalateralRatio;
		const y2 = y + size / 2;
		const x3 = x + size * this.equalateralRatio;
		const y3 = y + size / 2;
		polygonDom.setAttribute('points', `${x1},${y1} ${x2},${y2} ${x3},${y3}`);
	}

	destory() {
		cancelAnimationFrame(this.animation);
		this.svg = null;
		window.removeEventListener('visibilitychange', this.onVisibilityChange.bind(this));
	}

	randomBetween(min, max) {
		return Math.random() * (max - min) + min;
	}

	randomShade() {
		const shade = 1.025 + (Math.random() - 0.5) * 0.175;
		const color = this.baseColor.map(c => Math.round(c * shade));
		return `rgb(${color.join(',')})`;
	}

	onVisibilityChange() {
		if (document.hidden) {
			cancelAnimationFrame(this.animation);
		} else {
			this.lastTime = null;
			this.animation = requestAnimationFrame(this.tick.bind(this));
		}
	}
}

document.addEventListener('DOMContentLoaded', () => {
	if (!document.querySelector('#background')) return;
	window.triangleAnimation = new Triangles(document.querySelector('#background'));
});