const compose = (...fns) => x => fns.reduceRight((y, f) => f(y), x);

const flattenArray = arr => [].concat(...arr);

const isString = v => typeof v === 'string';

const isNumber = v => typeof v === 'number' && isFinite(v);

const isBoolean = v => typeof v === 'boolean';

const isArray = v => Array.isArray(v);

const toString = v => isString(v) ? v : '';

const toArray = v => isArray(v) ? v : [];

const notEmptyArray = v => isArray(v) && v.length > 0;

export const notEmptyString = v => isString(v) && v.trim().length > 0;

export const optionalString = v => (isString(v) && v.trim().length > 0) || v === undefined;

export const optionalNumber = v => isNumber(v) || v === undefined;

export const optionalBoolean = v => isBoolean(v) || v === undefined;

export const notEmptyStringArray = compose(v => (v.every(notEmptyString) && notEmptyArray(v)), toArray);

export const stringOrEmptyArray = compose(v => v.every(notEmptyString), toArray);

const executeValidator = (validator, value, object) => validator.test(value, object) ? ({status: true}) : ({
  status: false,
  message: validator.message
});

const executeValidators = (validators, value, object) => validators.map(validator => executeValidator(validator, value, object));

const getAllResults = (validators, object) => {
  let results = Object.keys(validators).map(k => {
    let result = executeValidators(validators[k] || [], object[k], object);
    let validationErrors = result.filter(v => !v.status && v.message);
    if (validationErrors.length) {
      return validationErrors;
    }
  }).filter(v => v);

  return flattenArray(results);
};

export const validateObject = (validators) => {
  return function (configObject) {
    const allResults = getAllResults(validators, configObject);
    if (allResults.length) {
      let errorMessage = 'CloudentityAuth: ';
      allResults.forEach((r, i) => i === allResults.length - 1 ? errorMessage += r.message : errorMessage += `${r.message}, `);
      return errorMessage;
    } else {
      return null;
    }
  };
};
