'use strict';

const path = require('path');

require('babel-loader');

const here = subpath => path.resolve(__dirname, subpath);

module.exports = env => {
  return {
    // devtool: 'source-map',
    entry: {
      'cloudentity-auth': here('src/index.js'),
    },
    output: {
      filename: '[name].js',
      path: here('dist'),
      publicPath: '/',
      library: 'CloudentityAuth',
      libraryTarget: 'umd',
      umdNamedDefine: true
    },
    resolve: {
      extensions: ['.js']
    },
    module: {
      rules: [
        {
          test: /\.js$/,
          exclude: /node_modules/,
          use: [
            {
              loader: 'babel-loader',
              options: {
                presets: ['es2015', 'stage-3'],
                plugins: ['transform-runtime']
              }
            }
          ],
        },
      ]
    },
    plugins: [
    ],
  };
};
