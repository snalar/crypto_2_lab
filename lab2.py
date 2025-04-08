import random
import tkinter as tk
import scipy.stats as stats
import numpy as np
from tkinter import messagebox, filedialog

def calculate_lfsr_period(polynomial, seed):
    state = seed
    seen_states = {}
    count = 0

    while state not in seen_states:
        seen_states[state] = count
        feedback = 0
        for power in polynomial:
            feedback ^= (state >> power) & 1
        state = ((state << 1) | feedback) & 0xFF
        count += 1

    return count - seen_states[state]

def check_cycles(data, max_cycle_length=100):
    for cycle_length in range(1, max_cycle_length + 1):
        if data[:cycle_length] == data[cycle_length:2*cycle_length]:
            return cycle_length
    return None


def chi_square_uniformity_test(data):
    observed_freq = [0] * 256
    for byte in data:
        observed_freq[byte] += 1

    expected_freq = [len(data) / 256] * 256
    chi2_stat, p_value = stats.chisquare(observed_freq, expected_freq)

    return chi2_stat, p_value

def check_balance(data):
    bit_count = sum(bin(byte).count('1') for byte in data)
    total_bits = len(data) * 8
    balance_ratio = bit_count / total_bits
    return balance_ratio



def autocorrelation(data, lag=1):
    data = np.frombuffer(data, dtype=np.uint8).astype(float)  # Преобразование
    n = len(data)
    mean = np.mean(data)
    autocorr = np.correlate(data - mean, np.roll(data - mean, -lag))[0] / np.var(data) / n
    return autocorr




def generate_random_key(length):
    return bytes(random.randint(0, 255) for _ in range(length))

def xor_encrypt(data, key):
    return bytes(d ^ k for d, k in zip(data, key))

def read_from_file(file_path):
    with open(file_path, "rb") as file:
        return file.read()

def save_to_file(file_path, data):
    with open(file_path, "wb") as file:
        file.write(data)

def lfsr_scrambler(data, polynomial, seed):
    state = seed
    scrambled_data = bytearray()
    states = []
    for byte in data:
        states.append(state)
        scrambled_byte = byte ^ state
        scrambled_data.append(scrambled_byte)
        feedback = 0
        for power in polynomial:
            feedback ^= (state >> power) & 1
        state = ((state << 1) | feedback) & 0xFF
    return bytes(scrambled_data), states

def lfsr_descrambler(data, polynomial, seed):
    state = seed
    descrambled_data = bytearray()
    states = []
    for byte in data:
        states.append(state)
        descrambled_byte = byte ^ state
        descrambled_data.append(descrambled_byte)
        feedback = 0
        for power in polynomial:
            feedback ^= (state >> power) & 1
        state = ((state << 1) | feedback) & 0xFF
    return bytes(descrambled_data), states

def perform_task():
    try:
        input_file = input_file_var.get()
        encrypted_file = output_file_var.get() + "_encrypted"
        key_file = output_file_var.get() + "_key"
        scrambled_file = output_file_var.get() + "_scrambled"
        descrambled_file = output_file_var.get() + "_descrambled"
        descrambled_file2 = output_file_var.get() + "_descrambled2"
        decrypted_file = output_file_var.get() + "_decrypted"

        plaintext = read_from_file(input_file)
        plaintext_length = len(plaintext)

        key_input = key_entry.get().strip()
        if key_input:
            try:
                key = bytes.fromhex(key_input)
            except ValueError:
                messagebox.showerror("Ошибка", "Некорректный формат ключа! Введите шестнадцатеричное значение.")
                return

            if len(key) < plaintext_length:
                key += generate_random_key(plaintext_length - len(key))
        else:
            key = generate_random_key(plaintext_length)

        encrypted_data = xor_encrypt(plaintext, key)
        save_to_file(encrypted_file, encrypted_data)
        save_to_file(key_file, key)

        # Скремблер 1
        scrambled_data_1, states_scrambler1 = lfsr_scrambler(encrypted_data, [5, 4, 2, 0], 0b10101010)
        save_to_file(scrambled_file, scrambled_data_1)

        descrambled_data_1, states_descrambler1 = lfsr_descrambler(scrambled_data_1, [5, 4, 2, 0], 0b10101010)
        save_to_file(descrambled_file, plaintext)

        # Скремблер 2
        scrambled_data_2, states_scrambler2 = lfsr_scrambler(encrypted_data, [5, 2, 0], 0b10101010)
        save_to_file(scrambled_file, scrambled_data_2)

        descrambled_data_2, states_descrambler2 = lfsr_descrambler(scrambled_data_2, [5, 2, 0], 0b10101010)
        save_to_file(descrambled_file2, plaintext)

        decrypted_data = xor_encrypt(descrambled_data_2, key)
        save_to_file(decrypted_file, decrypted_data)

        # Отображение ключей и состояний
        key_binary = ' '.join(format(byte, '08b') for byte in key)
        key_hex = ' '.join(format(byte, '02X') for byte in key)
        

        result_text.insert(tk.END, "Шифрование завершено.\n\n")
        result_text.insert(tk.END, "ГАММИРОВАНИЕ\n")
        result_text.insert(tk.END, f"Ключ : {key}\n")
        result_text.insert(tk.END, f"Ключ (2СС): {key_binary}\n")
        result_text.insert(tk.END, f"Ключ (16СС): {key_hex}\n\n")

        def format_states(states):
            binary = ' '.join(format(s, '08b') for s in states)
            hexed = ' '.join(format(s, '02X') for s in states)
            return binary, hexed
        
        period_scrambler1 = calculate_lfsr_period([5, 4, 2, 0], 0b10101010)
        period_scrambler2 = calculate_lfsr_period([5, 2, 0], 0b10101010)

        chi2_stat, p_value = chi_square_uniformity_test(encrypted_data)

        balance_ratio = check_balance(encrypted_data)

        autocorr = autocorrelation(encrypted_data)

        bin1, hex1 = format_states(states_scrambler1)
        result_text.insert(tk.END, "Скремблер 1 состояния:\n")
        result_text.insert(tk.END, f"Период скремблера 1: {period_scrambler1}\n")
        result_text.insert(tk.END, "[5, 4, 2, 0]\n")
        result_text.insert(tk.END, f"Статистика хи-квадрат: {chi2_stat}, p-значение: {p_value}\n")
        result_text.insert(tk.END, f"Коэффициент сбалансированности: {balance_ratio}\n")
        cycle_length = check_cycles(encrypted_data)
        if cycle_length:
            result_text.insert(tk.END, f"Обнаружена цикличность с длиной цикла: {cycle_length}\n")
        else:
            result_text.insert(tk.END, "Цикличность не обнаружена\n")
        result_text.insert(tk.END, f"Автокорреляция: {autocorr}\n")
        result_text.insert(tk.END, f"(2СС): {bin1}\n")
        result_text.insert(tk.END, f"(16СС): {hex1}\n\n")

        bin2, hex2 = format_states(states_scrambler2)
        result_text.insert(tk.END, "Скремблер 2 состояния:\n")
        result_text.insert(tk.END, f"Период скремблера 1: {period_scrambler2}\n")
        result_text.insert(tk.END, "[5, 2, 0]\n")
        result_text.insert(tk.END, f"Статистика хи-квадрат: {chi2_stat}, p-значение: {p_value}\n")
        result_text.insert(tk.END, f"Коэффициент сбалансированности: {balance_ratio}\n")
        cycle_length = check_cycles(encrypted_data)
        if cycle_length:
            result_text.insert(tk.END, f"Обнаружена цикличность с длиной цикла: {cycle_length}\n")
        else:
            result_text.insert(tk.END, "Цикличность не обнаружена\n")
        result_text.insert(tk.END, f"Автокорреляция: {autocorr}\n")
        result_text.insert(tk.END, f"(2СС): {bin2}\n")
        result_text.insert(tk.END, f"(16СС): {hex2}\n\n")

    except FileNotFoundError as e:
        messagebox.showerror("Ошибка", str(e))
    except Exception as e:
        messagebox.showerror("Ошибка", f"Произошла ошибка: {str(e)}")


root = tk.Tk()
root.title("Лабораторная 2")

main_frame = tk.Frame(root)
main_frame.pack(fill=tk.BOTH, expand=True)

output_frame = tk.Frame(main_frame)
output_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

result_text = tk.Text(output_frame, height=50, width=60, font=("Arial", 10), wrap=tk.WORD)
result_text.pack(fill=tk.BOTH, expand=True)
result_text.insert(tk.END, "Результат\n")

control_frame = tk.Frame(main_frame)
control_frame.pack(side=tk.RIGHT, fill=tk.Y, padx=5, pady=5)

instruction_label = tk.Label(control_frame, text="Выберите файлы и ключ.", font=("Arial", 12), justify="center")
instruction_label.pack(pady=10)

def import_data():
    file_path = filedialog.askopenfilename(title="Выберите входной файл", filetypes=[("All Files", "*.*")])
    input_file_var.set(file_path)

def export_data():
    file_path = filedialog.asksaveasfilename(title="Выберите выходной файл", defaultextension=".txt", filetypes=[("All Files", "*.*")])
    output_file_var.set(file_path)

input_button = tk.Button(control_frame, text="Выбрать входной файл", command=import_data, font=("Arial", 12))
input_button.pack(pady=5)

output_button = tk.Button(control_frame, text="Выбрать выходной файл", command=export_data, font=("Arial", 12))
output_button.pack(pady=5)

key_label = tk.Label(control_frame, text="Введите ключ (16СС):", font=("Arial", 10))
key_label.pack(pady=5)
key_entry = tk.Entry(control_frame, font=("Arial", 12))
key_entry.pack(pady=5)

run_button = tk.Button(control_frame, text="Зашифровать", command=perform_task, font=("Arial", 12))
run_button.pack(pady=10)

input_file_var = tk.StringVar()
output_file_var = tk.StringVar()

root.mainloop()