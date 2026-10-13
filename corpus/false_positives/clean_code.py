def calculate_percentage(obtained: float, maximum: float) -> float:
    """Calculates student percentage with validation."""
    if maximum <= 0:
        raise ValueError("Maximum marks must be greater than zero.")
    if obtained < 0:
        raise ValueError("Obtained marks cannot be negative.")
    return (obtained / maximum) * 100.0
