import tkinter as tk
from tkinter import ttk, filedialog as fd, simpledialog, messagebox
import base64

def encode_data(data):
    return base64.b64encode(data.encode()).decode()

def decode_data(encoded_data):
    return base64.b64decode(encoded_data.encode()).decode()

class SecureDataApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Secure Data Management")
        self.master.geometry("600x400")

        self.data = ""
        self.filename = ""

        self.admin_username = "admin"
        self.admin_password = "password"

        self.create_widgets()

    def authenticate_admin(self):
        username = simpledialog.askstring("Login", "Enter Admin Username:")
        password = simpledialog.askstring("Login", "Enter Admin Password:")

        if username == self.admin_username and password == self.admin_password:
            return True
        else:
            messagebox.showerror("Authentication Failed", "Invalid credentials. Access denied.")
            return False

    def create_customer(self):
        if not self.authenticate_admin():
            return

        email = self.email_entry.get()
        name = self.name_entry.get()
        payment_method = self.payment_method_entry.get()

        if not email or not name or not payment_method:
            messagebox.showerror("Error", "Please fill in all fields")
            return

        self.data = f"Email: {email}\nName: {name}\nPayment Method: {payment_method}"
        self.display_data()

    def load_data(self):
        if not self.authenticate_admin():
            return

        file_path = fd.askopenfilename()
        if not file_path:
            return

        with open(file_path, "r") as file:
            encoded_data = file.read()

        self.data = decode_data(encoded_data)
        self.display_data()

    def save_data(self):
        if not self.authenticate_admin():
            return

        if not self.data:
            messagebox.showerror("Error", "No data to save.")
            return

        encoded_data = encode_data(self.data)

        file_path = fd.asksaveasfilename()
        if not file_path:
            return

        with open(file_path, "w") as file:
            file.write(encoded_data)

    def clear_entry_fields(self):
        self.email_entry.delete(0, tk.END)
        self.name_entry.delete(0, tk.END)
        self.payment_method_entry.delete(0, tk.END)

    def display_data(self):
        self.text_area.delete(1.0, tk.END)
        self.text_area.insert(tk.END, self.data)

    def create_widgets(self):
        self.frame = ttk.Frame(self.master, padding="10")
        self.frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        ttk.Label(self.frame, text="Email:").grid(row=0, column=0, sticky=tk.W)
        self.email_entry = ttk.Entry(self.frame)
        self.email_entry.grid(row=0, column=1, sticky=tk.W)

        ttk.Label(self.frame, text="Name:").grid(row=1, column=0, sticky=tk.W)
        self.name_entry = ttk.Entry(self.frame)
        self.name_entry.grid(row=1, column=1, sticky=tk.W)

        ttk.Label(self.frame, text="Payment Method:").grid(row=2, column=0, sticky=tk.W)
        self.payment_method_entry = ttk.Entry(self.frame)
        self.payment_method_entry.grid(row=2, column=1, sticky=tk.W)

        ttk.Button(self.frame, text="Create Customer", command=self.create_customer).grid(row=3, column=0, columnspan=2, pady=5)
        ttk.Button(self.frame, text="Load Data", command=self.load_data).grid(row=4, column=0, pady=5)
        ttk.Button(self.frame, text="Save Data", command=self.save_data).grid(row=4, column=1, pady=5)

        self.text_area = tk.Text(self.frame, height=10, width=50)
        self.text_area.grid(row=5, column=0, columnspan=2, pady=5)

if __name__ == "__main__":
    root = tk.Tk()
    app = SecureDataApp(root)
    root.mainloop()
