from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import os
from functools import wraps
import random
import string

app = Flask(__name__)

# --- Configuration ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bank.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_key_that_is_hard_to_guess')

db = SQLAlchemy(app)

# --- Database Models ---
class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    address = db.Column(db.String(200))
    contact_info = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    accounts = db.relationship('Account', backref='customer', lazy=True, cascade="all, delete-orphan") # Added cascade for deletion
    loans = db.relationship('Loan', backref='customer', lazy=True, cascade="all, delete-orphan") # Added cascade for deletion

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<Customer {self.name}>"

class Account(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    account_number = db.Column(db.String(20), unique=True, nullable=False)
    account_type = db.Column(db.String(50), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    opening_date = db.Column(db.DateTime, default=datetime.utcnow)

    transactions = db.relationship('Transaction', backref='account', lazy=True, foreign_keys='[Transaction.account_id]', cascade="all, delete-orphan") # Added cascade
    outgoing_transfers = db.relationship('Transaction', backref='target_account', lazy=True, foreign_keys='[Transaction.target_account_id]')


    def __repr__(self):
        return f"<Account {self.account_number}>"

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_id = db.Column(db.Integer, db.ForeignKey('account.id'), nullable=False)
    transaction_type = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    description = db.Column(db.String(200))
    target_account_id = db.Column(db.Integer, db.ForeignKey('account.id'), nullable=True)

    def __repr__(self):
        return f"<Transaction {self.transaction_type} on {self.date}>"

class Loan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey('customer.id'), nullable=False)
    account_id = db.Column(db.Integer, db.ForeignKey('account.id'), nullable=False)
    loan_amount = db.Column(db.Float, nullable=False)
    interest_rate = db.Column(db.Float, nullable=False)
    term_months = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(50), default='Pending', nullable=False)
    application_date = db.Column(db.DateTime, default=datetime.utcnow)
    approval_date = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<Loan {self.id} - {self.status}>"

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<Admin {self.username}>"

# --- Helper function to require admin login ---
def admin_login_required(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            flash('Please log in to access the admin panel.', 'warning')
            return redirect(url_for('admin_login'))
        return view_func(*args, **kwargs)
    return decorated_function

# --- Helper function to require customer login ---
def customer_login_required(view_func):
    @wraps(view_func)
    def decorated_function(*args, **kwargs):
        if 'customer_id' not in session:
            flash('Please log in to access your account.', 'warning')
            return redirect(url_for('customer_login'))
        return view_func(*args, **kwargs)
    return decorated_function


# --- Flask Routes ---

@app.route('/')
def index():
    if 'customer_id' in session:
         return redirect(url_for('customer_dashboard'))
    if 'admin_id' in session:
        return redirect(url_for('admin_dashboard'))

    return render_template('index.html')

# --- Admin Routes ---

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if 'admin_id' in session:
        flash('You are already logged in as Admin.', 'info')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        admin = Admin.query.filter_by(username=username).first()

        if admin and admin.check_password(password):
            session['admin_id'] = admin.id
            flash('Logged in successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('admin_login.html')

@app.route('/admin/dashboard')
@admin_login_required
def admin_dashboard():
    total_customers = Customer.query.count()
    total_accounts = Account.query.count()
    latest_transactions = Transaction.query.order_by(Transaction.date.desc()).limit(10).all()
    pending_loans_count = Loan.query.filter_by(status='Pending').count()

    return render_template('admin_dashboard.html',
                           total_customers=total_customers,
                           total_accounts=total_accounts,
                           latest_transactions=latest_transactions,
                           pending_loans_count=pending_loans_count)


@app.route('/admin/logout')
@admin_login_required
def admin_logout():
    session.pop('admin_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('admin_login'))

# --- Admin Routes for Customer Management ---

@app.route('/admin/customers')
@admin_login_required
def admin_view_customers():
    customers = Customer.query.order_by(Customer.id).all() # Order by ID for consistency
    return render_template('admin_customers.html', customers=customers)

@app.route('/admin/customer/<int:customer_id>')
@admin_login_required
def admin_view_customer_details(customer_id):
    customer = Customer.query.get_or_404(customer_id)

    customer_accounts = customer.accounts
    customer_loans = customer.loans

    account_ids = [acc.id for acc in customer_accounts]
    customer_transactions = []
    if account_ids:
        customer_transactions = Transaction.query.filter(Transaction.account_id.in_(account_ids)).order_by(Transaction.date.desc()).all()

    return render_template('admin_customer_details.html',
                           customer=customer,
                           customer_accounts=customer_accounts,
                           customer_loans=customer_loans,
                           customer_transactions=customer_transactions)

# --- Admin Route for Editing Specific Customer Details ---
@app.route('/admin/customer/<int:customer_id>/edit', methods=['GET', 'POST'])
@admin_login_required
def admin_edit_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)

    if request.method == 'POST':
        # Get updated data from the form
        customer.name = request.form.get('name')
        customer.address = request.form.get('address')
        customer.contact_info = request.form.get('contact_info')
        # NOTE: Password is NOT edited here. A separate password reset mechanism would be needed.

        # Basic Validation
        if not customer.name or not customer.contact_info:
            flash('Name and Contact Info are required.', 'danger')
            # Pass back form data and customer object to repopulate the form
            return render_template('admin_edit_customer.html', customer=customer, form_data=request.form)

        # Check if the updated contact_info is already taken by *another* customer
        existing_customer_with_contact = Customer.query.filter_by(contact_info=customer.contact_info).first()
        if existing_customer_with_contact and existing_customer_with_contact.id != customer.id:
             flash('This contact info is already used by another customer.', 'danger')
             # Pass back form data and customer object
             return render_template('admin_edit_customer.html', customer=customer, form_data=request.form)


        try:
            db.session.commit() # Commit changes to the database
            flash(f'Customer "{customer.name}" details updated successfully!', 'success')
            return redirect(url_for('admin_view_customer_details', customer_id=customer.id)) # Redirect to the customer's detail page
        except Exception as e:
            db.session.rollback() # Rollback in case of error
            flash(f'Error updating customer: {str(e)}', 'danger')
            print(f"Error updating customer: {e}")
            # Pass back form data and customer object
            return render_template('admin_edit_customer.html', customer=customer, form_data=request.form)


    # For GET request, render the edit form with current customer data
    return render_template('admin_edit_customer.html', customer=customer, form_data=customer.__dict__) # Pass customer data as form_data


# --- Admin Route for Deleting Specific Customer ---
@app.route('/admin/customer/<int:customer_id>/delete', methods=['POST'])
@admin_login_required
def admin_delete_customer(customer_id):
    customer = Customer.query.get_or_404(customer_id)

    try:
        # Check if the customer has accounts with non-zero balance or active loans
        # In a real bank, you'd prevent deletion or transfer funds/loans first
        # For simplicity here, we use cascade="all, delete-orphan" in models,
        # which will delete associated accounts, loans, and transactions automatically.
        # Be EXTREMELY cautious with real data and cascade delete!

        db.session.delete(customer) # Mark the customer for deletion
        db.session.commit() # Commit the deletion

        flash(f'Customer "{customer.name}" and all associated data deleted successfully.', 'success')
        return redirect(url_for('admin_view_customers')) # Redirect back to the customer list

    except Exception as e:
        db.session.rollback() # Rollback in case of error
        flash(f'Error deleting customer: {str(e)}', 'danger')
        print(f"Error deleting customer: {e}")
        # Redirect back to the customer list or details page
        return redirect(url_for('admin_view_customer_details', customer_id=customer.id))


@app.route('/admin/add_customer', methods=['GET', 'POST'])
@admin_login_required
def admin_add_customer():
    if request.method == 'POST':
        name = request.form.get('name')
        address = request.form.get('address')
        contact_info = request.form.get('contact_info')

        if not name or not contact_info:
            flash('Name and Contact Info are required.', 'danger')
            return redirect(url_for('admin_add_customer'))

        existing_customer = Customer.query.filter_by(contact_info=contact_info).first()
        if existing_customer:
            flash('A customer with this contact info already exists. They can use the registration page to create an account.', 'danger')
            return redirect(url_for('admin_add_customer'))

        new_customer = Customer(name=name, address=address, contact_info=contact_info)

        db.session.add(new_customer)

        try:
            db.session.commit()
            flash(f'Customer "{name}" added successfully! They can now register for an account.', 'success')
            return redirect(url_for('admin_view_customers'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error adding customer: {str(e)}', 'danger')
            print(f"Error adding customer: {e}")
            return redirect(url_for('admin_add_customer'))

    return render_template('admin_add_customer.html')


# --- Admin Route for Transaction Management ---
@app.route('/admin/transactions')
@admin_login_required
def admin_view_transactions():
    transactions = Transaction.query.order_by(Transaction.date.desc()).all()
    return render_template('admin_transactions.html', transactions=transactions)

# --- Admin Route for Account Management ---
@app.route('/admin/accounts')
@admin_login_required
def admin_view_accounts():
    accounts = Account.query.order_by(Account.account_number).all()
    return render_template('admin_accounts.html', accounts=accounts)

# --- Admin Routes for Loan Management ---
@app.route('/admin/loans')
@admin_login_required
def admin_view_loans():
    loans = Loan.query.order_by(Loan.application_date.desc()).all()
    return render_template('admin_loans.html', loans=loans)

@app.route('/admin/loan/<int:loan_id>')
@admin_login_required
def admin_view_loan_details(loan_id):
    loan = Loan.query.get_or_404(loan_id)
    return render_template('admin_loan_details.html', loan=loan)


@app.route('/admin/loan/<int:loan_id>/approve', methods=['POST'])
@admin_login_required
def admin_approve_loan(loan_id):
    loan = Loan.query.get_or_404(loan_id)

    if loan.status == 'Pending':
        try:
            loan.status = 'Approved'
            loan.approval_date = datetime.utcnow()

            account = Account.query.get(loan.account_id)
            if account:
                account.balance += loan.loan_amount

                new_transaction = Transaction(
                    account_id=account.id,
                    transaction_type='Loan Disbursement',
                    amount=loan.loan_amount,
                    description=f'Loan #{loan.id} disbursed'
                )
                db.session.add(new_transaction)
            else:
                 flash(f'Account for loan #{loan.id} not found!', 'danger')
                 db.session.rollback()
                 return redirect(url_for('admin_view_loan_details', loan_id=loan.id))


            db.session.commit()
            flash(f'Loan #{loan.id} approved and disbursed successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error approving loan: {str(e)}', 'danger')
            print(f"Error approving loan: {e}")
    elif loan.status == 'Approved':
         flash(f'Loan #{loan.id} is already approved.', 'info')
    else:
         flash(f'Loan #{loan.id} has status "{loan.status}" and cannot be approved.', 'warning')


    return redirect(url_for('admin_view_loan_details', loan_id=loan.id))


@app.route('/admin/loan/<int:loan_id>/reject', methods=['POST'])
@admin_login_required
def admin_reject_loan(loan_id):
    loan = Loan.query.get_or_404(loan_id)

    if loan.status == 'Pending':
        try:
            loan.status = 'Rejected'
            loan.approval_date = datetime.utcnow()
            db.session.commit()
            flash(f'Loan #{loan.id} rejected.', 'warning')
        except Exception as e:
            db.session.rollback()
            flash(f'Error rejecting loan: {str(e)}', 'danger')
            print(f"Error rejecting loan: {e}")
    else:
         flash(f'Loan #{loan.id} has status "{loan.status}" and cannot be rejected.', 'warning')

    return redirect(url_for('admin_view_loan_details', loan_id=loan.id))


# --- Admin Route for Reporting (Placeholder) ---
@app.route('/admin/reports')
@admin_login_required
def admin_reports():
    # Keeping this as a placeholder for complex reporting
    flash("Reporting feature is not fully implemented.", 'info')
    return render_template('admin_reports.html')


# --- Customer Routes ---

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'customer_id' in session:
        flash('You are already logged in.', 'info')
        return redirect(url_for('customer_dashboard'))

    if request.method == 'POST':
        name = request.form.get('name')
        address = request.form.get('address')
        contact_info = request.form.get('contact_info')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        account_type = request.form.get('account_type')

        if not name or not contact_info or not password or not confirm_password or not account_type:
            flash('All fields are required.', 'danger')
            return render_template('register.html', form_data=request.form)

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html', form_data=request.form)

        existing_customer = Customer.query.filter_by(contact_info=contact_info).first()
        if existing_customer:
            flash('A customer with this contact info already exists. Please log in or use a different contact.', 'danger')
            return render_template('register.html', form_data=request.form)

        new_customer = Customer(name=name, address=address, contact_info=contact_info)
        new_customer.set_password(password)

        db.session.add(new_customer)

        try:
            db.session.commit()

            account_number = str(random.randint(1000000000, 9999999999))
            existing_account = Account.query.filter_by(account_number=account_number).first()
            while existing_account:
                 account_number = str(random.randint(1000000000, 9999999999))
                 existing_account = Account.query.filter_by(account_number=account_number).first()


            new_account = Account(
                customer_id=new_customer.id,
                account_number=account_number,
                account_type=account_type,
                balance=0.0
            )

            db.session.add(new_account)
            db.session.commit()

            flash('Registration successful! Please log in with your contact info and password.', 'success')
            return redirect(url_for('customer_login'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error during registration: {str(e)}', 'danger')
            print(f"Error during registration: {e}")
            return render_template('register.html', form_data=request.form)

    return render_template('register.html', form_data={})


@app.route('/login', methods=['GET', 'POST'])
def customer_login():
    if 'customer_id' in session:
        flash('You are already logged in.', 'info')
        return redirect(url_for('customer_dashboard'))

    if request.method == 'POST':
        contact_info = request.form.get('contact_info')
        password = request.form.get('password')

        customer = Customer.query.filter_by(contact_info=contact_info).first()

        if customer and customer.check_password(password):
            session['customer_id'] = customer.id
            flash('Logged in successfully!', 'success')
            return redirect(url_for('customer_dashboard'))
        else:
            flash('Invalid contact info or password.', 'danger')

    return render_template('customer_login.html')


@app.route('/dashboard')
@customer_login_required
def customer_dashboard():
    customer_id = session['customer_id']
    customer = Customer.query.get(customer_id)

    if customer is None:
         session.pop('customer_id', None)
         flash('Your account could not be loaded. Please log in again.', 'danger')
         return redirect(url_for('customer_login'))

    customer_accounts = customer.accounts
    customer_loans = customer.loans

    return render_template('customer_dashboard.html',
                           customer=customer,
                           customer_accounts=customer_accounts,
                           customer_loans=customer_loans)


@app.route('/account/<int:account_id>/transactions')
@customer_login_required
def customer_view_account_transactions(account_id):
    customer_id = session['customer_id']
    account = Account.query.filter_by(id=account_id, customer_id=customer_id).first_or_404()

    account_transactions = Transaction.query.filter_by(account_id=account_id).order_by(Transaction.date.desc()).all()

    return render_template('customer_account_transactions.html',
                           account=account,
                           transactions=account_transactions)


# --- Customer Banking Operations ---

@app.route('/account/<int:account_id>/deposit', methods=['GET', 'POST'])
@customer_login_required
def customer_deposit(account_id):
    customer_id = session['customer_id']
    account = Account.query.filter_by(id=account_id, customer_id=customer_id).first_or_404()

    if request.method == 'POST':
        amount = request.form.get('amount', type=float)

        if amount is None or amount <= 0:
            flash('Invalid deposit amount.', 'danger')
            return redirect(url_for('customer_deposit', account_id=account.id))

        account.balance += amount

        new_transaction = Transaction(
            account_id=account.id,
            transaction_type='Deposit',
            amount=amount,
            description='Online Deposit'
        )

        db.session.add(new_transaction)

        try:
            db.session.commit()
            flash(f'Successfully deposited ₹{amount:.2f} into Account {account.account_number}.', 'success')
            return redirect(url_for('customer_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error processing deposit: {str(e)}', 'danger')
            print(f"Error processing deposit: {e}")
            return redirect(url_for('customer_deposit', account_id=account.id))


    return render_template('customer_deposit.html', account=account)


@app.route('/account/<int:account_id>/withdraw', methods=['GET', 'POST'])
@customer_login_required
def customer_withdraw(account_id):
    customer_id = session['customer_id']
    account = Account.query.filter_by(id=account_id, customer_id=customer_id).first_or_404()

    if request.method == 'POST':
        amount = request.form.get('amount', type=float)

        if amount is None or amount <= 0:
            flash('Invalid withdrawal amount.', 'danger')
            return redirect(url_for('customer_withdraw', account_id=account.id))

        if account.balance < amount:
            flash('Insufficient funds.', 'danger')
            return redirect(url_for('customer_withdraw', account_id=account.id))

        account.balance -= amount

        new_transaction = Transaction(
            account_id=account.id,
            transaction_type='Withdrawal',
            amount=amount,
            description='Online Withdrawal'
        )

        db.session.add(new_transaction)

        try:
            db.session.commit()
            flash(f'Successfully withdrew ₹{amount:.2f} from Account {account.account_number}.', 'success')
            return redirect(url_for('customer_dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error processing withdrawal: {str(e)}', 'danger')
            print(f"Error processing withdrawal: {e}")
            return redirect(url_for('customer_withdraw', account_id=account.id))

    return render_template('customer_withdraw.html', account=account)


@app.route('/account/<int:account_id>/transfer', methods=['GET', 'POST'])
@customer_login_required
def customer_transfer(account_id):
    customer_id = session['customer_id']
    source_account = Account.query.filter_by(id=account_id, customer_id=customer_id).first_or_404()

    if request.method == 'POST':
        target_account_number = request.form.get('target_account_number')
        amount = request.form.get('amount', type=float)
        description = request.form.get('description')

        if amount is None or amount <= 0:
            flash('Invalid transfer amount.', 'danger')
            return redirect(url_for('customer_transfer', account_id=source_account.id))

        if not target_account_number:
             flash('Target account number is required.', 'danger')
             return redirect(url_for('customer_transfer', account_id=source_account.id))

        target_account = Account.query.filter_by(account_number=target_account_number).first()

        if not target_account:
            flash('Target account not found.', 'danger')
            return redirect(url_for('customer_transfer', account_id=source_account.id))

        if source_account.id == target_account.id:
            flash('Cannot transfer to the same account.', 'danger')
            return redirect(url_for('customer_transfer', account_id=source_account.id))

        if source_account.balance < amount:
            flash('Insufficient funds in the source account.', 'danger')
            return redirect(url_for('customer_transfer', account_id=source_account.id))

        try:
            source_account.balance -= amount
            debit_transaction = Transaction(
                account_id=source_account.id,
                transaction_type='Transfer (Debit)',
                amount=amount,
                description=f'Transfer to Account {target_account.account_number}' + (f': {description}' if description else ''),
                target_account_id=target_account.id
            )
            db.session.add(debit_transaction)

            target_account.balance += amount
            credit_transaction = Transaction(
                account_id=target_account.id,
                transaction_type='Transfer (Credit)',
                amount=amount,
                description=f'Transfer from Account {source_account.account_number}' + (f': {description}' if description else ''),
                target_account_id=source_account.id
            )
            db.session.add(credit_transaction)

            db.session.commit()
            flash(f'Successfully transferred ₹{amount:.2f} from Account {source_account.account_number} to Account {target_account.account_number}.', 'success')
            return redirect(url_for('customer_dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error processing transfer: {str(e)}', 'danger')
            print(f"Error processing transfer: {e}")
            return redirect(url_for('customer_transfer', account_id=source_account.id))

    return render_template('customer_transfer.html', account=source_account)

# --- Customer Loan Operations ---

@app.route('/loan/apply', methods=['GET', 'POST'])
@customer_login_required
def customer_apply_loan():
    customer_id = session['customer_id']
    customer = Customer.query.get(customer_id)
    customer_accounts = customer.accounts

    if request.method == 'POST':
        loan_amount = request.form.get('loan_amount', type=float)
        term_months = request.form.get('term_months', type=int)
        interest_rate = request.form.get('interest_rate', type=float)
        account_id = request.form.get('account_id', type=int)

        if loan_amount is None or loan_amount <= 0 or term_months is None or term_months <= 0 or interest_rate is None or interest_rate < 0 or account_id is None:
            flash('Invalid loan details.', 'danger')
            return render_template('customer_apply_loan.html', customer_accounts=customer_accounts, form_data=request.form)

        target_account = Account.query.filter_by(id=account_id, customer_id=customer_id).first()
        if not target_account:
            flash('Invalid account selected for disbursement.', 'danger')
            return render_template('customer_apply_loan.html', customer_accounts=customer_accounts, form_data=request.form)

        new_loan = Loan(
            customer_id=customer.id,
            account_id=target_account.id,
            loan_amount=loan_amount,
            interest_rate=interest_rate,
            term_months=term_months,
            status='Pending'
        )

        db.session.add(new_loan)

        try:
            db.session.commit()
            flash('Loan application submitted successfully. Status is Pending.', 'success')
            return redirect(url_for('customer_view_loans'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error submitting loan application: {str(e)}', 'danger')
            print(f"Error submitting loan application: {e}")
            return render_template('customer_apply_loan.html', customer_accounts=customer_accounts, form_data=request.form)

    return render_template('customer_apply_loan.html', customer_accounts=customer_accounts, form_data={})

@app.route('/loan/status')
@customer_login_required
def customer_view_loans():
    customer_id = session['customer_id']
    customer = Customer.query.get(customer_id)
    customer_loans = customer.loans

    return render_template('customer_view_loans.html', customer_loans=customer_loans)


@app.route('/logout')
@customer_login_required
def customer_logout():
    session.pop('customer_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('customer_login'))


# --- Database Initialization ---
with app.app_context():
    db.create_all()
    print("Database and tables created (or already exist)!")

    initial_admin_username = os.environ.get('INITIAL_ADMIN_USERNAME', 'admin')
    initial_admin_password = os.environ.get('INITIAL_ADMIN_PASSWORD', 'password123')

    existing_admin = Admin.query.filter_by(username=initial_admin_username).first()

    if not existing_admin:
        new_admin = Admin(username=initial_admin_username)
        new_admin.set_password(initial_admin_password)
        db.session.add(new_admin)
        try:
            db.session.commit()
            print(f"Initial admin user '{initial_admin_username}' created with default password.")
            print("IMPORTANT: Please change the default password immediately for security.")
        except Exception as e:
             db.session.rollback()
             print(f"Error creating initial admin: {e}")
             if "UNIQUE constraint failed: admin.username" in str(e):
                 print(f"Admin username '{initial_admin_username}' already exists.")
             else:
                 print("An unexpected error occurred during initial admin creation.")


if __name__ == '__main__':
    app.run(debug=True)