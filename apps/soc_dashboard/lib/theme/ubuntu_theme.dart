import 'package:flutter/material.dart';

class UbuntuTheme {
  // Ubuntu Yaru Brand Colors
  static const Color ubuntuOrange = Color(0xFFE95420);
  static const Color ubuntuAubergine = Color(0xFF77216F);
  static const Color ubuntuWarmGray = Color(0xFFAEA79F);

  // Status Colors (Granular Hue Spectrum)
  static const Color statusGreen = Color(0xFF26A269);      // 0 - 25% (Nominal)
  static const Color statusLime = Color(0xFF73C936);       // 25 - 50% (Low concern)
  static const Color statusYellow = Color(0xFFE5A50A);     // 50 - 70% (Caution)
  static const Color statusOrange = Color(0xFFF57900);     // 70 - 85% (75% High Risk Alert)
  static const Color statusRed = Color(0xFFC01C28);        // 85 - 100% (Critical Incident)

  static Color getGranularHealthColor(double riskPercent) {
    if (riskPercent < 0.25) {
      return Color.lerp(statusGreen, statusLime, riskPercent / 0.25)!;
    } else if (riskPercent < 0.50) {
      return Color.lerp(statusLime, statusYellow, (riskPercent - 0.25) / 0.25)!;
    } else if (riskPercent < 0.75) {
      return Color.lerp(statusYellow, statusOrange, (riskPercent - 0.50) / 0.25)!;
    } else {
      return Color.lerp(statusOrange, statusRed, (riskPercent - 0.75) / 0.25)!;
    }
  }

  // Authentic Ubuntu Yaru Dark Palette (Warm grays and charcoal, NO dark blues)
  static final ThemeData darkTheme = ThemeData(
    useMaterial3: true,
    brightness: Brightness.dark,
    scaffoldBackgroundColor: const Color(0xFF1E1E1E), // Ubuntu Shell Dark Gray
    colorScheme: const ColorScheme.dark(
      primary: ubuntuOrange,
      secondary: ubuntuAubergine,
      surface: Color(0xFF2B2B2B), // GNOME Card Gray
      surfaceContainerHighest: Color(0xFF383838), // Header & Divider Gray
      onSurface: Color(0xFFF6F6F6),
      onPrimary: Colors.white,
      outline: Color(0xFF444444),
    ),
    fontFamily: 'Monaco',
    fontFamilyFallback: const ['Ubuntu Mono', 'DejaVu Sans Mono', 'monospace'],
    cardTheme: CardThemeData(
      color: const Color(0xFF2B2B2B),
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(10),
        side: const BorderSide(color: Color(0xFF383838), width: 1),
      ),
    ),
    dialogTheme: DialogThemeData(
      backgroundColor: const Color(0xFF2B2B2B),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: const BorderSide(color: Color(0xFF484848), width: 1),
      ),
    ),
  );

  // Authentic Ubuntu Yaru Light Palette (Clean warm porcelain and silver)
  static final ThemeData lightTheme = ThemeData(
    useMaterial3: true,
    brightness: Brightness.light,
    scaffoldBackgroundColor: const Color(0xFFF5F5F5), // Ubuntu Shell Light
    colorScheme: const ColorScheme.light(
      primary: ubuntuOrange,
      secondary: ubuntuAubergine,
      surface: Color(0xFFFFFFFF), // Pure White Card
      surfaceContainerHighest: Color(0xFFE8E8E8), // Header Gray
      onSurface: Color(0xFF222222),
      onPrimary: Colors.white,
      outline: Color(0xFFD6D6D6),
    ),
    fontFamily: 'Monaco',
    fontFamilyFallback: const ['Ubuntu Mono', 'DejaVu Sans Mono', 'monospace'],
    cardTheme: CardThemeData(
      color: const Color(0xFFFFFFFF),
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(10),
        side: const BorderSide(color: Color(0xFFE2E2E2), width: 1),
      ),
    ),
    dialogTheme: DialogThemeData(
      backgroundColor: const Color(0xFFFFFFFF),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: const BorderSide(color: Color(0xFFCCCCCC), width: 1),
      ),
    ),
  );
}
