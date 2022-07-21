import { expect } from 'chai';
import 'mocha';

import { getController } from './common';

const fragment = 'z6MkhVTX9BF3NGYX6cc7jWpbNnR7cAjH8LUffabZP8Qu4ysC'
const controller = `did:key:${fragment}`;
const identifier = `${controller}#${fragment}`;

describe('Common test',
  () => {
    it('should parse controller', () => {
      const result = getController(identifier);
      expect(result).to.equal(controller);
    });
  });
