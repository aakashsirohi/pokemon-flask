# app.py

from collections import defaultdict
from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import (
    StringField,
    TextAreaField,
    FloatField,
    SubmitField,
    PasswordField,
    SubmitField,
    StringField,
    PasswordField,
    SubmitField,
)
from wtforms.validators import DataRequired, Length, EqualTo
from werkzeug.security import generate_password_hash, check_password_hash

import requests

app = Flask(__name__)
app.config[
    "SECRET_KEY"
] = b"c5f106a29285bf65e7aaf70c971091cd"  # Change this to a random string
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///pokemon.db"
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = "login"


class User(db.Model, UserMixin):  # User Schema
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    team = db.relationship("Team", backref="user", lazy=True)


class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    pokemon_name = db.Column(db.String(50), nullable=False)
    base_stats_hp = db.Column(db.Integer, nullable=False)
    base_stats_attack = db.Column(db.Integer, nullable=False)
    base_stats_defense = db.Column(db.Integer, nullable=False)
    image_url = db.Column(db.String(255), nullable=False)
    abilities = db.Column(db.String(255), nullable=False)

    def calculate_total_attack(self):
        if not hasattr(self, "_total_attack"):
            self._total_attack = (
                self.base_stats_hp + self.base_stats_attack + self.base_stats_defense
            )
        return self._total_attack


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current Password", validators=[DataRequired()])
    new_password = PasswordField(
        "New Password", validators=[DataRequired(), Length(min=8)]
    )
    confirm_new_password = PasswordField(
        "Confirm New Password", validators=[DataRequired(), EqualTo("new_password")]
    )
    submit = SubmitField("Change Password")


class PokemonForm(FlaskForm):  # PokemonForm
    pokemon_name = StringField("Pokemon Name", validators=[DataRequired()])
    submit = SubmitField("Get Pokemon Info", render_kw={"class": "button-class"})


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
@app.route("/home")
def home():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Corrected line
        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            flash("Username already exists. Choose a different one.", "danger")
        else:
            new_user = User(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash("Account created successfully. You can now log in.", "success")
            return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if user and user.password == password:
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("index"))
        else:
            flash("Login failed. Check your username and password.", "danger")

    return render_template("login.html")


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    form = ChangePasswordForm()

    if form.validate_on_submit():
        # Check if the current password provided matches the user's actual password
        if current_user.password == form.current_password.data:
            current_user.password = form.new_password.data
            db.session.commit()
            flash("Your password has been changed successfully.", "success")
            return redirect(url_for("index"))
        else:
            flash("Current password is incorrect.", "danger")

    return render_template("change-password.html", form=form)


@app.route("/index", methods=["GET", "POST"])
@login_required
def index():
    form = PokemonForm()
    if form.validate_on_submit():
        pokemon_name = form.pokemon_name.data.lower()
        pokemon_data = get_pokemon_data(pokemon_name)
        if pokemon_data:
            return render_template("pokemon-info.html", pokemon_data=pokemon_data)
        else:
            flash(
                f'Pokemon "{pokemon_name}" not found. Please enter a valid Pokemon name.',
                "danger",
            )
    return render_template("get-info.html", form=form)


def get_pokemon_data(pokemon_name):
    try:
        response = requests.get(f"https://pokeapi.co/api/v2/pokemon/{pokemon_name}/")
        data = response.json()
        return {
            "name": data["name"],
            "base_stats": {
                "hp": data["stats"][0]["base_stat"],
                "attack": data["stats"][1]["base_stat"],
                "defense": data["stats"][2]["base_stat"],
            },
            "sprites": {
                "front_shiny": data["sprites"]["front_shiny"],
            },
            "abilities": [ability["ability"]["name"] for ability in data["abilities"]],
        }
    except requests.exceptions.RequestException:
        return None


@app.route("/add_to_team/<pokemon_name>", methods=["POST"])
@login_required
def add_to_team(pokemon_name):
    # Check if the Pokémon is already in the user's team
    existing_team_member = Team.query.filter_by(
        user_id=current_user.id, pokemon_name=pokemon_name
    ).first()
    if existing_team_member:
        flash(f"{pokemon_name} is already in your team!", "info")
    elif len(current_user.team) >= 6:
        flash(
            f"You already have {len(current_user.team)} Pokémon in your team. You cannot add more.",
            "info",
        )
    else:
        # Get Pokémon data
        pokemon_data = get_pokemon_data(pokemon_name)
        if pokemon_data:
            # Add the Pokémon to the user's team
            team_member = Team(
                user_id=current_user.id,
                pokemon_name=pokemon_name,
                base_stats_hp=pokemon_data["base_stats"]["hp"],
                base_stats_attack=pokemon_data["base_stats"]["attack"],
                base_stats_defense=pokemon_data["base_stats"]["defense"],
                image_url=pokemon_data["sprites"]["front_shiny"],
                abilities=", ".join(pokemon_data["abilities"]),
            )
            db.session.add(team_member)
            db.session.commit()
            flash(f"{pokemon_name} added to your team!", "success")
        else:
            flash(f"Failed to get information for {pokemon_name}.", "danger")

    return redirect(url_for("my_team"))


@app.route("/drop_from_team/<int:team_member_id>", methods=["POST"])
@login_required
def drop_from_team(team_member_id):
    team_member = Team.query.get(team_member_id)

    if team_member:
        # Check if the team member belongs to the current user
        if team_member.user_id == current_user.id:
            db.session.delete(team_member)
            db.session.commit()
            flash(f"{team_member.pokemon_name} dropped from your team!", "success")
        else:
            flash("You cannot drop a Pokémon that does not belong to you.", "danger")
    else:
        flash("Team member not found.", "danger")

    return redirect(url_for("my_team"))


@app.route("/my_team")
@login_required
def my_team():
    team_members = Team.query.filter_by(user_id=current_user.id).all()
    return render_template("my_team.html", team_members=team_members)


@app.route("/battle", methods=["GET", "POST"])
@login_required
def battle():
    if request.method == "POST":
        opponent_user_id = request.form.get("opponent_user_id")
        opponent_teams = Team.query.filter_by(user_id=opponent_user_id).all()

        if not opponent_teams:
            flash("Opponent teams not found!", "danger")
            return redirect(url_for("battle"))
        # Calculate total attack stats for the opponent
        opponent_total_attack = sum(
            team.calculate_total_attack() for team in opponent_teams
        )
        print(
            f"Opponent Total Attack: {opponent_total_attack}"
        )  # Add this line for debugging

        # Calculate total attack stats for the current user's teams
        user_teams = Team.query.filter(Team.user != current_user).all()
        user_total_attack = sum(team.calculate_total_attack() for team in user_teams)
        print(f"User Total Attack: {user_total_attack}")  # Add this line for debugging

        print(
            f"Opponent Attack Stats: {[team.calculate_total_attack() for team in opponent_teams]}"
        )
        print(
            f"User Attack Stats: {[team.calculate_total_attack() for team in user_teams]}"
        )

        if user_total_attack > opponent_total_attack:
            flash("Congratulations! You have won!", "success")
        elif user_total_attack == opponent_total_attack:
            flash("It is a tie!", "info")
        else:
            flash("Oops! You lost", "danger")

        return redirect(url_for("battle"))

    teams = Team.query.filter(Team.user != current_user).all()
    # Organize the teams by user_id
    user_teams = defaultdict(list)
    for team in teams:
        user_teams[team.user_id].append(team)

    return render_template("battle.html", user_teams=user_teams)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logout successful!", "success")
    return redirect(url_for("home"))


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
