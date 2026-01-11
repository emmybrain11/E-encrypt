class ConnectScreen(Screen):
    connection_status = StringProperty("Not Connected")
    status_color = ListProperty([1, 0.3, 0.3,
                                 1])  # Default red

    def on_connection_status(self, instance, value):
        """Update color when status changes"""
        if value == 'Connected':
            self.status_color = [0.3, 0.7, 0.3, 1]  # Green
        else:
            self.status_color = [1, 0.3, 0.3, 1]  # Red