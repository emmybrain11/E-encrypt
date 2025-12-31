import os

# Force software rendering for your laptop
os.environ['KIVY_GL_BACKEND'] = 'angle_sdl2'
os.environ['KIVY_GRAPHICS'] = 'gles'

from kivy.app import App
from kivy.lang import Builder
from kivy.uix.screenmanager import ScreenManager, Screen

KV = '''
ScreenManager:
    EntryScreen:
    CalculatorScreen:
    RealVaultScreen:

<EntryScreen>:
    name: 'entry'
    BoxLayout:
        orientation: 'vertical'
        padding: 50
        spacing: 20
        Label:
            text: "SECURE ACCESS GATE"
            font_size: '24sp'
        TextInput:
            id: auth_input
            password: True
            multiline: False
            size_hint_y: None
            height: '45dp'
        Button:
            text: "LOGIN"
            on_press: root.check_auth(auth_input.text)

<CalculatorScreen>:
    name: 'calc'
    BoxLayout:
        orientation: 'vertical'
        TextInput:
            id: display
            text: '0'
            font_size: '45sp'
            readonly: True
            size_hint_y: 0.2
        GridLayout:
            cols: 4
            Button:
                text: "7"
                on_press: display.text = self.text if display.text == '0' else display.text + self.text
            Button:
                text: "AC"
                on_press: display.text = '0'
            Button:
                text: "ENTER"
                on_press: root.verify_calc_code(display.text)

<RealVaultScreen>:
    name: 'vault'
    BoxLayout:
        orientation: 'vertical'
        padding: 10
        spacing: 10
        Label:
            text: "ENCRYPTED MESSENGER"
            size_hint_y: None
            height: '40dp'
            color: 0, 1, 0.5, 1

        ScrollView:
            Label:
                id: chat_logs
                text: "--- Secure Session Started ---"
                size_hint_y: None
                height: self.texture_size[1]
                text_size: self.width, None
                halign: 'left'
                valign: 'top'

        BoxLayout:
            size_hint_y: None
            height: '50dp'
            spacing: 5
            TextInput:
                id: msg_in
                multiline: False
                hint_text: "Type a message..."
            Button:
                text: "SEND"
                size_hint_x: 0.25
                on_press: root.send_text(msg_in.text)

        BoxLayout:
            size_hint_y: None
            height: '50dp'
            spacing: 10
            Button:
                text: "UPLOAD PHOTO"
                on_press: root.open_file_picker()
            Button:
                text: "PANIC"
                background_color: 1, 0, 0, 1
                on_press: root.panic_exit()
'''


class EntryScreen(Screen):
	def check_auth(self, val):
		if val == "112233":
			self.manager.current = 'vault'
		else:
			self.manager.current = 'calc'


class CalculatorScreen(Screen):
	def verify_calc_code(self, val):
		if val == "112233":
			self.manager.current = 'vault'
		else:
			self.ids.display.text = "0"


class RealVaultScreen(Screen):
	def send_text(self, text):
		if text.strip():
			self.ids.chat_logs.text += f"\n[YOU]: {text}"
			self.ids.msg_in.text = ""

	def open_file_picker(self):
		# Placeholder for picture sending logic
		self.ids.chat_logs.text += "\n[SYSTEM]: Photo selected (encrypted)"

	def panic_exit(self):
		self.manager.current = 'calc'


class EEncryptApp(App):
	def build(self):
		return Builder.load_string(KV)


if __name__ == '__main__':
	EEncryptApp().run()