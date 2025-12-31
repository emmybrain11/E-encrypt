
from kivy.app import App
from kivy.lang import Builder

KV = '''
BoxLayout:
    Button:
        text: "Kivy Works"
'''

class TestApp(App):
    def build(self):
        return Builder.load_string(KV)

TestApp().run()