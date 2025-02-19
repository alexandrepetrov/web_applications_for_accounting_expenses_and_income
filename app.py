from datetime import datetime
import os
from flask_wtf import FlaskForm
from wtforms import DateField, StringField, TextAreaField, RadioField, SelectMultipleField, SubmitField
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, abort, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from wtforms import StringField, FloatField, SelectField, SubmitField, PasswordField
from wtforms.validators import DataRequired, EqualTo
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import func
from flask_wtf.file import FileField, FileRequired
from werkzeug.utils import secure_filename
import csv
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///survey.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'  # Папка для временного хранения файлов

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Модель пользователя
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    transactions = db.relationship('Transaction', backref='user', lazy=True)

# Модель Transaction
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    date = db.Column(db.DateTime, nullable=False)

class TransactionForm(FlaskForm):
    amount = FloatField('Сумма', validators=[DataRequired()])
    category = StringField('Категория', validators=[DataRequired()])
    date = DateField('Дата', validators=[DataRequired()])
    submit = SubmitField('Добавить')


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class ImportForm(FlaskForm):
    file = FileField('Файл для импорта', validators=[FileRequired()])
    submit = SubmitField('Импорт')
# Создаем папку для загрузок, если она не существует
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Загрузчик пользователя для Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Кастомный ModelView с проверкой прав доступа
class AdminModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.username == 'admin'

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))

# Инициализация Flask-Admin
admin = Admin(app, name='Админка', template_mode='bootstrap3')
admin.add_view(AdminModelView(User, db.session))
admin.add_view(AdminModelView(Transaction, db.session))


class RegistrationForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    confirm_password = PasswordField('Подтвердите пароль', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Зарегистрироваться')

class LoginForm(FlaskForm):
    username = StringField('Имя пользователя', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()  # Создаем экземпляр формы
    if form.validate_on_submit():  # Проверяем, отправлена ли форма и валидна ли она
        username = form.username.data
        password = form.password.data
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Регистрация прошла успешно! Теперь вы можете войти.')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)  # Передаем форму в шаблон


# Вход
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Вы успешно вошли в систему!')
            return redirect(url_for('dashboard'))  # Перенаправление на защищенную страницу
        else:
            flash('Неверное имя пользователя или пароль.')

    return render_template('login.html', form=form)

# Выход
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.')
    return redirect(url_for('login'))

# Маршрут для отображения формы
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = TransactionForm()

    # Обработка отправки формы
    if form.validate_on_submit():
        try:
            # Создаем новую транзакцию
            new_transaction = Transaction(
                user_id=current_user.id,
                amount=form.amount.data,
                category=form.category.data,
                date=form.date.data
            )
            db.session.add(new_transaction)
            db.session.commit()
            flash('Транзакция успешно добавлена!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Ошибка при добавлении транзакции: {e}', 'error')

    # Получаем все транзакции текущего пользователя
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date).all()

    # Вычисляем общий баланс
    balance = sum(t.amount for t in transactions)

    # Группируем данные по категориям
    stats = {}
    for t in transactions:
        stats[t.category] = stats.get(t.category, 0) + t.amount

    # Разделяем доходы и расходы
    income = {k: v for k, v in stats.items() if v > 0}
    expenses = {k: abs(v) for k, v in stats.items() if v < 0}

    # Собираем статистику по категориям
    stats = db.session.query(
        Transaction.category,
        func.sum(Transaction.amount).label('total')
    ).filter_by(user_id=current_user.id).group_by(Transaction.category).all()

    # Преобразуем результат в словарь
    stats_dict = {category: total for category, total in stats}

    # Передаем данные в шаблон
    return render_template('dashboard.html', balance=balance, stats=stats_dict, form=form, income=income, expenses=expenses)

@app.route('/import_export', methods=['GET', 'POST'])
@login_required
def import_export():
    form = ImportForm()
    if form.validate_on_submit():
        file = form.file.data
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Обработка файла в зависимости от расширения
        if filename.endswith('.csv'):
            process_csv(file_path)
        elif filename.endswith('.json'):
            process_json(file_path)
        else:
            flash('Неподдерживаемый формат файла', 'error')
            return redirect(url_for('import_export'))

        flash('Данные успешно импортированы!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('import_export.html', form=form)

def process_csv(file_path):
    """Обработка CSV-файла."""
    with open(file_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                transaction = Transaction(
                    amount=float(row['amount']),
                    category=row['category'],
                    date=datetime.strptime(row['date'], '%Y-%m-%d %H:%M:%S'),
                    user_id=current_user.id
                )
                db.session.add(transaction)
            except Exception as e:
                flash(f'Ошибка при обработке строки: {row}. Ошибка: {str(e)}', 'error')
        db.session.commit()

def process_json(file_path):
    """Обработка JSON-файла."""
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        for item in data:
            try:
                transaction = Transaction(
                    amount=float(item['amount']),
                    category=item['category'],
                    date=datetime.strptime(item['date'], '%Y-%m-%d %H:%M:%S'),
                    user_id=current_user.id
                )
                db.session.add(transaction)
            except Exception as e:
                flash(f'Ошибка при обработке элемента: {item}. Ошибка: {str(e)}', 'error')
        db.session.commit()

# Маршрут /export
@app.route('/export_data')
@login_required
def export_data():
    transactions = Transaction.query.filter_by(user_id=current_user.id).all()
    data = [{'amount': t.amount, 'category': t.category, 'date': t.date} for t in transactions]
    return jsonify(data)

# Создание таблиц в базе данных
with app.app_context():
    db.create_all()
# Проверка, существует ли пользователь 'admin'
    admin_user = User.query.filter_by(username='admin').first()
    if not admin_user:
        # Создание пользователя 'admin', если он не существует
        admin_user = User(username='admin', password=generate_password_hash('admin123'))
        db.session.add(admin_user)
        db.session.commit()
        print("Пользователь 'admin' создан.")
    else:
        print("Пользователь 'admin' уже существует.")



if __name__ == '__main__':
    app.run(debug=True)