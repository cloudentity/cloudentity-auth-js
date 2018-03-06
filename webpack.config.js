'use strict';

const path = require('path');

require('babel-loader');

const here = subpath => path.resolve(__dirname, subpath);

module.exports = env => {
  return {
    // devtool: 'source-map',
    entry: {
      'cloudentity-web-auth': here('src/index.js'),
    },
    output: {
      filename: '[name].js',
      path: here('dist'),
      publicPath: '/',
      library: 'CloudentityWebAuth',
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
          use: [
            {
              loader: 'babel-loader',
              options: {
                presets: ['es2015'],
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
