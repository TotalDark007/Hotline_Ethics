from datetime import datetime, timedelta
import random
import secrets

from werkzeug.security import generate_password_hash

from app import create_app
from extensions import db
from models import Report, User


def humane_sentence(rtype, who, dept, place, day_str):
    templates = [
        f"Reported {rtype.replace('_',' ').lower()} involving {who} from {dept} at {place} on {day_str}.",
        f"Anonymous note describes concerns of {rtype.replace('_',' ').lower()} by {who} ({dept}) near {place} on {day_str}.",
        f"Colleague observed potential {rtype.replace('_',' ').lower()} around {place}; mentioned {who} from {dept} ({day_str}).",
        f"Potential incident related to {rtype.replace('_',' ').lower()} was raised about {who} ({dept}) at {place} on {day_str}.",
    ]
    return random.choice(templates)


def main():
    app = create_app()
    with app.app_context():
        db.create_all()

        # Seed users
        users = [
            {"name": "Alex Singh", "email": "alex.singh@company.com", "role": "investigator", "password": "Password!123"},
            {"name": "Maya Patel", "email": "maya.patel@company.com", "role": "admin", "password": "Password!123"},
        ]
        for u in users:
            if not User.query.filter_by(email=u["email"]).first():
                user = User(name=u["name"], email=u["email"], role=u["role"], password_hash=generate_password_hash(u["password"]))
                db.session.add(user)

        # Seed reports
        existing = Report.query.count()
        target_total = 120
        to_add = max(0, target_total - existing)

        types = [
            "Fraud", "Harassment", "Discrimination", "Safety_Violation",
            "Conflict_of_Interest", "Bribery", "Environmental_Violation", "Mismanagement", "Other"
        ]
        statuses = ["New", "Ongoing", "Resolved"]
        weights = [0.3, 0.4, 0.3]

        names = [
            "John M.", "Priya K.", "Luis R.", "Emily T.", "Chen W.",
            "Nadia H.", "Omar F.", "Sara B.", "Hannah D.", "Mark J."
        ]
        depts = ["Finance", "Marketing", "Operations", "HR", "Engineering", "Legal", "Sales"]
        places = ["open workspace", "meeting room A", "cafeteria", "loading bay", "parking level 2", "remote call"]

        now = datetime.utcnow()
        for _ in range(to_add):
            rtype = random.choice(types)
            status = random.choices(statuses, weights=weights, k=1)[0]
            days_ago = random.randint(0, 180)
            hours_offset = random.randint(0, 23)
            ts = now - timedelta(days=days_ago, hours=hours_offset)
            who = random.choice(names)
            dept = random.choice(depts)
            place = random.choice(places)
            day_str = ts.strftime('%Y-%m-%d')
            details = humane_sentence(rtype, who, dept, place, day_str)

            contact = "" if random.random() < 0.6 else random.choice([
                f"{who.split()[0].lower()}.{who.split()[0].lower()}@example.com",
                "+1 415-555-0%03d" % random.randint(0, 999),
                "prefer not to disclose"
            ])

            report = Report(
                timestamp=ts,
                status=status,
                report_type=rtype,
                report_details=details,
                anonymous_contact=contact,
                access_code=secrets.token_urlsafe(8),
                password_hash=generate_password_hash("demo1234"),
                file_name=None,
            )
            db.session.add(report)

        db.session.commit()
        print(f"Seed complete. Users ensured. Reports total: {Report.query.count()}.")


if __name__ == "__main__":
    main()

