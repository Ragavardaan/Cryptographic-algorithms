# app.py
from flask import Flask, render_template, request, redirect, url_for
import shift_cipher
import hill_cipher
import playfair_cipher
import primitive_root
import number_theory
import aes
import des_single
import rsa_algorithm
import diffie_hellman
import md5_algorithm
import cmac_des


app = Flask(__name__)

# --- Main Navigation Routes ---
@app.route('/')
def home():
    return render_template('home.html')

@app.route("/ex<int:num>")
def exercises(num):
    return render_template("index.html", active_ex=f"ex{num}")


@app.route('/shift_encrypt.html', methods=['GET', 'POST'])
def shift_encrypt_route():
    result, error = None, None
    if request.method == 'POST':
        try:
            pt = request.form.get('plaintext', '')
            key = request.form.get('key', '')
            result = shift_cipher.encrypt_shift(pt, key)
        except Exception as e: error = str(e)
    return render_template('shift_encrypt.html', result=result, error=error)

@app.route('/shift_decrypt.html', methods=['GET', 'POST'])
def shift_decrypt_route():
    result, error = None, None
    if request.method == 'POST':
        try:
            ct = request.form.get('ciphertext', '')
            key = request.form.get('key', '')
            result = shift_cipher.decrypt_shift(ct, key)
        except Exception as e: error = str(e)
    return render_template('shift_decrypt.html', result=result, error=error)

@app.route('/hill_encrypt.html', methods=['GET', 'POST'])
def hill_encrypt_route():
    result_data, error = None, None
    if request.method == 'POST':
        try:
            size = request.form.get('size', '')
            key_input = request.form.get('key', '')
            pt = request.form.get('plaintext')
            if not key_input:
                raise ValueError('Key/Matrix input is required.')
            # Try parsing as numeric matrix first, fall back to key text
            try:
                matrix = hill_cipher.parse_square_matrix(key_input, size if size != '' else None)
            except Exception as e_num:
                # try as key text
                try:
                    matrix = hill_cipher.parse_key_text(key_input, size if size != '' else None)
                except Exception as e_text:
                    raise ValueError(f"Could not parse key/matrix: {e_num}; {e_text}")
            result_data = hill_cipher.encrypt_hill(pt, matrix)
        except Exception as e: error = str(e)
    return render_template('hill_encrypt.html', data=result_data, error=error)

@app.route('/hill_decrypt.html', methods=['GET', 'POST'])
def hill_decrypt_route():
    result_data, error = None, None
    if request.method == 'POST':
        try:
            size = request.form.get('size', '')
            key_input = request.form.get('key', '')
            ct = request.form.get('ciphertext')
            if not key_input:
                raise ValueError('Key/Matrix input is required.')
            try:
                matrix = hill_cipher.parse_square_matrix(key_input, size if size != '' else None)
            except Exception as e_num:
                try:
                    matrix = hill_cipher.parse_key_text(key_input, size if size != '' else None)
                except Exception as e_text:
                    raise ValueError(f"Could not parse key/matrix: {e_num}; {e_text}")
            result_data = hill_cipher.decrypt_hill(ct, matrix)
        except Exception as e: error = str(e)
    return render_template('hill_decrypt.html', data=result_data, error=error)

@app.route('/hill_determinant.html', methods=['GET', 'POST'])
def hill_determinant_route():
    det, det_mod, error = None, None, None
    if request.method == 'POST':
        try:
            size = request.form.get('size')
            matrix = hill_cipher.parse_square_matrix(request.form.get('matrix'), size)
            d = hill_cipher.determinant(matrix)
            det, det_mod = d, hill_cipher.mod(d)
        except Exception as e: error = str(e)
    return render_template('hill_determinant.html', det=det, det_mod=det_mod, error=error)

@app.route('/hill_cofactor.html', methods=['GET', 'POST'])
def hill_cofactor_route():
    result, error = None, None
    if request.method == 'POST':
        try:
            size = request.form.get('size')
            matrix = hill_cipher.parse_square_matrix(request.form.get('matrix'), size)
            cof = hill_cipher.cofactor_matrix(matrix)
            result = "\n".join(" ".join(str(x) for x in row) for row in cof)
        except Exception as e: error = str(e)
    return render_template('hill_cofactor.html', result=result, error=error)

@app.route('/hill_transpose.html', methods=['GET', 'POST'])
def hill_transpose_route():
    result, error = None, None
    if request.method == 'POST':
        try:
            size = request.form.get('size')
            matrix = hill_cipher.parse_square_matrix(request.form.get('matrix'), size)
            trans = hill_cipher.transpose(matrix)
            result = "\n".join(" ".join(str(x) for x in row) for row in trans)
        except Exception as e: error = str(e)
    return render_template('hill_transpose.html', result=result, error=error)

@app.route('/hill_matrix_inverse.html', methods=['GET', 'POST'])
def hill_matrix_inverse_route():
    det, det_mod, det_inv, cofactor, inverse, error = None, None, None, None, None, None
    if request.method == 'POST':
        try:
            size = request.form.get('size')
            matrix = hill_cipher.parse_square_matrix(request.form.get('matrix'), size)
            
            d = hill_cipher.determinant(matrix)
            det = d
            det_mod = hill_cipher.mod(d)
            
            cof = hill_cipher.cofactor_matrix(matrix)
            cofactor = "\n".join(" ".join(str(x) for x in row) for row in cof)
            
            try:
                det_inv = hill_cipher.mod_inverse(det_mod)
                inv_m = hill_cipher.inverse_matrix_mod26(matrix)
                inverse = "\n".join(" ".join(str(x) for x in row) for row in inv_m)
            except Exception as e2:
                det_inv = "No Inverse"
                inverse = str(e2)
        except Exception as e: error = str(e)
    return render_template('hill_matrix_inverse.html', det=det, det_mod=det_mod, 
                           det_inv=det_inv, cofactor=cofactor, inverse=inverse, error=error)

@app.route('/hill_multiplicative_inverse.html', methods=['GET', 'POST'])
def hill_multiplicative_inverse_route():
    gcd_val, inverse, error = None, None, None
    if request.method == 'POST':
        try:
            a = int(request.form.get('a'))
            g, x = hill_cipher.extended_gcd(a, 26)
            gcd_val = g
            if g == 1: inverse = hill_cipher.mod(x, 26)
            else: inverse = "No Inverse"
        except Exception as e: error = str(e)
    return render_template('hill_multiplicative_inverse.html', gcd=gcd_val, inverse=inverse, error=error)

@app.route('/playfair_encrypt.html', methods=['GET', 'POST'])
def playfair_encrypt_route():
    result_data = None
    error = None
    if request.method == 'POST':
        try:
            pt = request.form.get('plaintext', '')
            key = request.form.get('key', '')
            # Returns dict: {'text':..., 'matrix':..., 'orig_pairs':..., 'trans_pairs':...}
            result_data = playfair_cipher.playfair_process(pt, key, 'encrypt')
        except Exception as e: error = str(e)
    return render_template('playfair_encrypt.html', data=result_data, error=error)

@app.route('/playfair_decrypt.html', methods=['GET', 'POST'])
def playfair_decrypt_route():
    result_data = None
    error = None
    if request.method == 'POST':
        try:
            ct = request.form.get('ciphertext', '')
            key = request.form.get('key', '')
            # Returns dict: {'text':..., 'matrix':..., 'orig_pairs':..., 'trans_pairs':...}
            result_data = playfair_cipher.playfair_process(ct, key, 'decrypt')
        except Exception as e: error = str(e)
    return render_template('playfair_decrypt.html', data=result_data, error=error)

@app.route('/primitive_root.html', methods=['GET', 'POST'])
def primitive_root_route():
    result = None
    error = None
    if request.method == 'POST':
        try:
            n_raw = request.form.get('modulus', '')
            n = int(n_raw)
            result = primitive_root.get_primitive_roots_info(n, show_steps=True)
        except Exception as e:
            error = str(e)
    return render_template('primitive_root.html', result=result, error=error, active_ex='ex1')

@app.route('/gcd.html', methods=['GET', 'POST'])
def gcd_route():
    result = None
    error = None
    if request.method == 'POST':
        try:
            a = request.form.get('a', '')
            b = request.form.get('b', '')
            result = number_theory.compute_gcd_display(a, b)
            if result['error']:
                error = result['error']
                result = None
        except Exception as e:
            error = str(e)
    return render_template('gcd.html', result=result, error=error)

@app.route('/extended_gcd.html', methods=['GET', 'POST'])
def extended_gcd_route():
    result = None
    error = None
    if request.method == 'POST':
        try:
            a = request.form.get('a', '')
            b = request.form.get('b', '')
            result = number_theory.compute_extended_gcd_display(a, b)
            if result['error']:
                error = result['error']
                result = None
        except Exception as e:
            error = str(e)
    return render_template('extended_gcd.html', result=result, error=error)


@app.route('/aes.html', methods=['GET', 'POST'])
def aes_route():
    result, error = None, None
    if request.method == 'POST':
        try:
            pt_text = request.form.get('plaintext_text', '').strip()
            key = request.form.get('key', '')
            mode = request.form.get('mode', 'ECB')
            operation = request.form.get('operation', 'ENCRYPT')
            pt = pt_text
            if pt == '':
                raise ValueError('Provide plaintext as text (characters).')
            result = aes.compute_aes_trace(pt, key, mode=mode, operation=operation)
        except Exception as e: error = str(e)
    return render_template('aes.html', result=result, error=error)


@app.route('/des.html', methods=['GET', 'POST'])
def des_route():
    result, error = None, None
    if request.method == 'POST':
        try:
            pt_text = request.form.get('plaintext_text', '').strip()
            key = request.form.get('key', '')
            mode = request.form.get('mode', 'ECB')
            operation = request.form.get('operation', 'ENCRYPT')
            pt = pt_text
            if pt == '':
                raise ValueError('Provide plaintext as text (characters).')
            result = des_single.compute_des_trace(pt, key, mode=mode, operation=operation)
        except Exception as e: error = str(e)
    return render_template('des.html', result=result, error=error)

@app.route('/rsa.html', methods=['GET', 'POST'])
def rsa_route():
    result = None
    error = None
    key_steps = None
    enc_steps = None
    dec_steps = None

    if request.method == 'POST':
        try:
            action = request.form.get('action')

            p = int(request.form.get('p'))
            q = int(request.form.get('q'))
            e = int(request.form.get('e'))

            key_data = rsa_algorithm.rsa_key_generation(p, q, e)
            key_steps = key_data['steps']
            n = key_data['n']
            d = key_data['d']

            if action == "generate":
                result = f"Public Key: ({e}, {n}) | Private Key: ({d}, {n})"

            elif action == "encrypt":
                message = request.form.get('message')
                result, enc_steps = rsa_algorithm.rsa_encrypt_auto(message, e, n)
            elif action == "decrypt":
                cipher_input = request.form.get('ciphertext')
                result, dec_steps = rsa_algorithm.rsa_decrypt_auto(cipher_input, d, n)


        except Exception as ex:
            error = str(ex)

    return render_template('rsa.html',
                           result=result,
                           error=error,
                           key_steps=key_steps,
                           enc_steps=enc_steps,
                           dec_steps=dec_steps)
@app.route('/diffie.html', methods=['GET','POST'])
def diffie_route():

    result=None
    error=None

    if request.method=='POST':
        try:

            q=int(request.form.get('q'))
            alpha=int(request.form.get('alpha'))

            a=request.form.get('a')
            b=request.form.get('b')

            a=int(a) if a else None
            b=int(b) if b else None

            result=diffie_hellman.diffie_hellman_process(q,alpha,a,b)

        except Exception as e:
            error=str(e)

    return render_template(
        'diffie.html',
        result=result,
        error=error
    )

@app.route('/md5.html', methods=['GET','POST'])
def md5_route():

    result = None
    error = None

    try:
        if request.method == 'POST':

            message = request.form.get('message')

            if not message:
                raise ValueError("Message cannot be empty")

            result = md5_algorithm.md5_hash_trace(message)

    except Exception as e:
        import traceback
        print(traceback.format_exc())  # helps debugging
        error = str(e)

    return render_template(
        'md5.html',
        result=result,
        error=error
    )

@app.route('/cmac.html', methods=['GET','POST'])
def cmac_route():

    result = None
    error = None

    try:
        if request.method == 'POST':

            message = request.form.get('message')
            n_bits = int(request.form.get('n_bits'))

            result = cmac_des.cmac_des(message, n_bits)

    except Exception as e:
        error = str(e)

    return render_template(
        'cmac.html',
        result=result,
        error=error
    )
if __name__ == '__main__':
    app.run()
