const canvas = document.getElementById('background');
const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
const renderer = new THREE.WebGLRenderer({ canvas, alpha: true });
renderer.setSize(window.innerWidth, window.innerHeight);

const geometry = new THREE.SphereGeometry(0.1, 24, 24);
const material = new THREE.MeshBasicMaterial({ color: 0x007bff });

const nodes = [];
for (let i = 0; i < 50; i++) {
    const node = new THREE.Mesh(geometry, material);
    node.position.set(
        (Math.random() - 0.5) * 10,
        (Math.random() - 0.5) * 10,
        (Math.random() - 0.5) * 10
    );
    scene.add(node);
    nodes.push(node);
}

camera.position.z = 5;

function animate() {
    requestAnimationFrame(animate);
    nodes.forEach((node) => {
        node.position.x += (Math.random() - 0.5) * 0.01;
        node.position.y += (Math.random() - 0.5) * 0.01;
        node.position.z += (Math.random() - 0.5) * 0.01;
    });
    renderer.render(scene, camera);
}
animate();

window.addEventListener('resize', () => {
    camera.aspect = window.innerWidth / window.innerHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(window.innerWidth, window.innerHeight);
});
