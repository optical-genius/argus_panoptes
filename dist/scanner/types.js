"use strict";
/**
 * Types and interfaces for Argus Panoptes DLP Engine
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.DetectionCategory = exports.SensitivitySeverity = void 0;
var SensitivitySeverity;
(function (SensitivitySeverity) {
    SensitivitySeverity["LOW"] = "low";
    SensitivitySeverity["MEDIUM"] = "medium";
    SensitivitySeverity["HIGH"] = "high";
    SensitivitySeverity["CRITICAL"] = "critical";
})(SensitivitySeverity || (exports.SensitivitySeverity = SensitivitySeverity = {}));
var DetectionCategory;
(function (DetectionCategory) {
    DetectionCategory["API_KEY"] = "API_KEY";
    DetectionCategory["JWT_TOKEN"] = "JWT_TOKEN";
    DetectionCategory["PRIVATE_KEY"] = "PRIVATE_KEY";
    DetectionCategory["DATABASE_CREDENTIAL"] = "DATABASE_CREDENTIAL";
    DetectionCategory["HIGH_ENTROPY_SECRET"] = "HIGH_ENTROPY_SECRET";
    DetectionCategory["FINNISH_HETU"] = "FINNISH_HETU";
    DetectionCategory["IBAN"] = "IBAN";
    DetectionCategory["CREDIT_CARD"] = "CREDIT_CARD";
    DetectionCategory["EMAIL"] = "EMAIL";
    DetectionCategory["PHONE_NUMBER"] = "PHONE_NUMBER";
    DetectionCategory["IP_ADDRESS"] = "IP_ADDRESS";
    DetectionCategory["CUSTOM_RULE"] = "CUSTOM_RULE";
})(DetectionCategory || (exports.DetectionCategory = DetectionCategory = {}));
//# sourceMappingURL=types.js.map