//A very selective port of only the necessary functions from MiiJS
//The authors of InfiniMii are also the authors of MiiJS

function miiHeightToMeasurements(value) {
    // h in [0, 127]
    const totalInches = 36 + (48 / 127) * value; // 3' to 7'
    return {
        feet: Math.floor(totalInches / 12),
        inches: Math.round(totalInches % 12),
        totalInches,
        
        centimeters: Math.round(totalInches * 2.54)
    };
}
function inchesToMiiHeight(totalInches) {
    return ((totalInches - 36) * 127) / 48;
}
function centimetersToMiiHeight(totalCentimeters) {
    return ((Math.round(totalCentimeters / 2.54) - 36) * 127) / 48;
}

// ---- Tunable anchors (BMI breakpoints) ----
const BMI_MIN = 16;
const BMI_MID = 22;
const BMI_MAX = 35;
function bmiFromWeightSlider(w) {
    // w in [0, 127]
    if (w <= 64) {
        return BMI_MID - (64 - w) * (BMI_MID - BMI_MIN) / 64;
    } else {
        return BMI_MID + (w - 64) * (BMI_MAX - BMI_MID) / 63;
    }
}
function miiWeightToMeasurements(heightInches, miiWeight) {
    /*
    Take the height, map it to a reasonable height 0-127 === 3'-7'.
    Get the average weight for that height.
    Take the slider 0-127 for weight, assume 64 is the average midpoint.
    If less than 64, make the Mii's weight more underweight than the average.
    If higher, make the Mii's weight more overweight than the average.
    The shorter the height, the less drastic the weight changes.
    
    This is approximate, not guaranteed accurate nor intended to be taken that way. This is for entertainment value only.
    */
    if (!heightInches || heightInches < 0) throw new Error("heightInches must be >= 0");
    const H = miiHeightToMeasurements(heightInches).totalInches;
    const BMI = bmiFromWeightSlider(miiWeight);
    return {
        pounds: BMI * (H * H) / 703,
        kilograms: Math.round((BMI * (H * H) / 703) * 0.4535924)
    };
}
const miiWeightToRealWeight = miiWeightToMeasurements;
function imperialHeightWeightToMiiWeight(heightInches, weightLbs) {
    if (!heightInches || heightInches < 0) throw new Error("heightInches must be >= 0");
    
    const H = miiHeightToMeasurements(heightInches).totalInches;
    const BMI = weightLbs * 703 / (H * H);
    
    if (BMI <= BMI_MID) {
        return 64 - 64 * (BMI_MID - BMI) / (BMI_MID - BMI_MIN);
    }
    else {
        return 64 + 63 * (BMI - BMI_MID) / (BMI_MAX - BMI_MID);
    }
}
function metricHeightWeightToMiiWeight(heightCentimeters, weightKilograms) {
    const heightInches = Math.round(heightCentimeters / 2.54);
    const weightLbs = Math.round(weightKilograms / 0.4535924);
    if (!heightInches || heightInches < 0) throw new Error("heightCentimeters must be >= 0");
    
    const H = miiHeightToMeasurements(heightInches).totalInches;
    const BMI = weightLbs * 703 / (H * H);
    
    if (BMI <= BMI_MID) {
        return 64 - 64 * (BMI_MID - BMI) / (BMI_MID - BMI_MIN);
    }
    else {
        return 64 + 63 * (BMI - BMI_MID) / (BMI_MAX - BMI_MID);
    }
}
