class StatusException implements Exception {
  int statusCode;
  String description;
  StatusException(this.statusCode, this.description);
}