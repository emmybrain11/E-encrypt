from kivy.uix.screenmanager import Screen
from security import encrypt_message
from database import save_message, load_messages

class ChatScreen(Screen):
    def on_pre_enter(self):
        self.refresh()

    def send_message(self):
        msg = self.ids.message.text
        if msg:
            encrypted = encrypt_message(msg)
            save_message(encrypted)
            self.ids.message.text = ""
            self.refresh()

    def refresh(self):
        messages = load_messages()
        self.ids.chat_log.text = "\n".join(m[0] for m in messages)
