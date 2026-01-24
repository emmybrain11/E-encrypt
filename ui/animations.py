from kivy.uix.widget import Widget
from kivy.graphics import Color, Ellipse, Rectangle, Line
from kivy.clock import Clock
from kivy.properties import ListProperty, NumericProperty
import random
import math
import colorsys


class WaterBackground(Widget):
    """Animated water effect background"""

    wave_points = ListProperty([])
    wave_speed = NumericProperty(0.5)
    wave_height = NumericProperty(20)
    wave_length = NumericProperty(100)
    color_hue = NumericProperty(0.6)  # Blue hue

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.wave_offset = 0
        self.color_offset = 0

        with self.canvas:
            # Background gradient
            self.bg_rect = Rectangle(pos=self.pos, size=self.size)

            # Wave
            self.wave_color = Color(rgba=self.get_wave_color())
            self.wave = Line(points=[], width=2)

        Clock.schedule_interval(self.update_wave, 1 / 60)
        Clock.schedule_interval(self.update_color, 0.1)

    def on_size(self, *args):
        self.bg_rect.size = self.size
        self.generate_wave_points()

    def generate_wave_points(self):
        """Generate wave points"""
        self.wave_points = []
        width = self.width

        for x in range(0, int(width), 5):
            y = self.height * 0.7 + math.sin(x / self.wave_length + self.wave_offset) * self.wave_height
            self.wave_points.extend([x, y])

    def get_wave_color(self):
        """Get dynamic wave color"""
        # Cycle through blue-green hues
        hue = (self.color_hue + math.sin(self.color_offset) * 0.1) % 1.0
        rgb = colorsys.hsv_to_rgb(hue, 0.7, 0.8)
        return (rgb[0], rgb[1], rgb[2], 0.7)

    def update_wave(self, dt):
        """Update wave animation"""
        self.wave_offset += self.wave_speed * dt
        self.generate_wave_points()
        self.wave.points = self.wave_points

    def update_color(self, dt):
        """Update color animation"""
        self.color_offset += 0.1
        rgba = self.get_wave_color()
        self.wave_color.rgba = rgba

        # Update background gradient
        dark_color = (rgba[0] * 0.2, rgba[1] * 0.2, rgba[2] * 0.2, 1)
        mid_color = (rgba[0] * 0.5, rgba[1] * 0.5, rgba[2] * 0.5, 1)

        # This would be a gradient shader in production
        self.bg_rect.source = self.create_gradient_texture(dark_color, mid_color)

    def create_gradient_texture(self, color1, color2):
        """Create gradient texture (simplified)"""
        # In production, use OpenGL shaders for gradient
        pass


class ParticleSystem(Widget):
    """Advanced particle system for background effects"""

    particle_count = NumericProperty(100)
    particle_speed = NumericProperty(1.0)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.particles = []
        self.init_particles()

        with self.canvas:
            self.particle_group = []

        Clock.schedule_interval(self.update_particles, 1 / 60)

    def init_particles(self):
        """Initialize particles"""
        for _ in range(self.particle_count):
            particle = {
                'x': random.uniform(0, self.width),
                'y': random.uniform(0, self.height),
                'size': random.uniform(2, 6),
                'speed_x': random.uniform(-1, 1) * self.particle_speed,
                'speed_y': random.uniform(-1, 1) * self.particle_speed,
                'color': (
                    random.uniform(0.1, 0.3),
                    random.uniform(0.4, 0.7),
                    random.uniform(0.8, 1.0),
                    random.uniform(0.3, 0.7)
                )
            }
            self.particles.append(particle)

    def update_particles(self, dt):
        """Update particle positions"""
        self.canvas.clear()

        with self.canvas:
            for particle in self.particles:
                # Update position
                particle['x'] += particle['speed_x']
                particle['y'] += particle['speed_y']

                # Bounce off edges
                if particle['x'] <= 0 or particle['x'] >= self.width:
                    particle['speed_x'] *= -1

                if particle['y'] <= 0 or particle['y'] >= self.height:
                    particle['speed_y'] *= -1

                # Keep within bounds
                particle['x'] = max(0, min(self.width, particle['x']))
                particle['y'] = max(0, min(self.height, particle['y']))

                # Draw particle
                Color(*particle['color'])
                Ellipse(
                    pos=(particle['x'], particle['y']),
                    size=(particle['size'], particle['size'])
                )

                # Draw connection lines
                for other in self.particles:
                    if other is particle:
                        continue

                    dx = particle['x'] - other['x']
                    dy = particle['y'] - other['y']
                    distance = math.sqrt(dx * dx + dy * dy)

                    if distance < 100:  # Connection distance
                        alpha = 1.0 - (distance / 100)
                        Color(0.3, 0.6, 1.0, alpha * 0.3)
                        Line(
                            points=[particle['x'], particle['y'], other['x'], other['y']],
                            width=1
                        )