import complement from 'ramda/es/complement';
import isEmpty from 'ramda/es/isEmpty';
import compose from 'ramda/es/compose';
import trim from 'ramda/es/trim';
import map from 'ramda/es/map';
import mapObjIndexed from 'ramda/es/mapObjIndexed';
import curry from 'ramda/es/curry';
import filter from 'ramda/es/filter';
import pickBy from 'ramda/es/pickBy';
import head from 'ramda/es/head';
import prop from 'ramda/es/prop';
import values from 'ramda/es/values';
import both from 'ramda/es/both';


const isObject = v => typeof v === 'object';

const isString = v => typeof v === 'string';

const isArray = v => typeof v === 'object' && v.length;

const toString = v => isString(v) ? v : '';

const toArray = v => isArray(v) ? v : [];

const toObject = v => isObject(v) ? v : {};

export const notEmpty = complement(isEmpty);

export const notEmptyString = compose(notEmpty, trim, toString);

export const onlyStrings = compose(isEmpty, filter(complement(isString)));

export const notEmptyStringArray = compose(both(notEmpty, onlyStrings), toArray);


const executeValidator = curry((validator, value, object) => validator.test(value, object) ? ({status: true}) : ({
  status: false,
  message: validator.message
}));

const executeValidators = curry((validators, value, object) => map(validator => executeValidator(validator, value, object), validators));

const getAllResults = (validators, object) => mapObjIndexed((v, k) => executeValidators(v || [], object[k], object), validators);

const leaveOnlyErrors = compose(pickBy(notEmpty), map(filter(v => !v.status)));

const getFirstMessage = compose(prop('message'), head);

export const validateObject = curry((validators, object) => compose(head, values, map(getFirstMessage), leaveOnlyErrors, getAllResults)(validators, toObject(object)));
